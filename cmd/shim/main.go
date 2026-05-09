package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/mayjain/aegis/internal/ipc"
	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/internal/risk"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	toolExecTimeout = 5 * time.Minute
	daemonEvalTimeout = 30 * time.Second
	toolShutdownGrace = 3 * time.Second
)

func main() {
	agentID := flag.String("agent-id", "", "Agent identity (required)")
	policyPath := flag.String("policies", "", "Policy YAML file path")
	socketPath := flag.String("socket", "", "Daemon Unix socket (optional)")
	logLevel := flag.String("log-level", "warn", "Log level")
	flag.Parse()

	toolCmd := flag.Args()
	if len(toolCmd) == 0 || *agentID == "" {
		fmt.Fprintln(os.Stderr, "Usage: aegis-shim --agent-id <id> [--policies <path>] [--socket <path>] -- <tool-command> [args...]")
		os.Exit(1)
	}

	logger := setupLogger(*logLevel)

	localEvaluator := loadLocalPolicy(*policyPath, logger)
	localScorer := createLocalScorer()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var daemonConn net.Conn
	var daemonMu sync.Mutex
	var daemonDone chan struct{}
	var pending sync.Map

	shimID := uuid.New().String()
	if *socketPath != "" {
		conn, done, err := connectAndRegister(*socketPath, shimID, *agentID, &pending, logger)
		if err != nil {
			logger.Warn("daemon unavailable, running standalone", "error", err)
		} else {
			daemonConn = conn
			daemonDone = done
			defer conn.Close()
		}
	}

	// Reconnection goroutine — recovers from daemon restarts
	if *socketPath != "" {
		go func() {
			delays := []time.Duration{500 * time.Millisecond, 1 * time.Second, 2 * time.Second}
			for {
				// Wait for disconnect (or context cancellation)
				select {
				case <-ctx.Done():
					return
			case <-daemonDone:
				// Daemon disconnected — attempt reconnect
			}

			logger.Info("daemon disconnected, attempting reconnect")
				reconnected := false
				for _, delay := range delays {
					time.Sleep(delay)
					select {
					case <-ctx.Done():
						return
					default:
					}

					conn, done, err := connectAndRegister(*socketPath, shimID, *agentID, &pending, logger)
					if err != nil {
						logger.Debug("reconnect attempt failed", "error", err, "delay", delay)
						continue
					}

					// Swap connection atomically
					daemonMu.Lock()
					daemonConn = conn
					daemonDone = done
					daemonMu.Unlock()

					logger.Info("reconnected to daemon")
					reconnected = true
					break
				}

				if !reconnected {
					logger.Warn("all reconnect attempts failed, continuing in standalone mode")
					// Create a new channel that will never close (don't retry again until explicit signal)
					standbyDone := make(chan struct{})
					daemonMu.Lock()
					daemonDone = standbyDone
					daemonMu.Unlock()
				}
			}
		}()
	}

	cmd := exec.Command(toolCmd[0], toolCmd[1:]...)
	cmd.Stderr = io.Discard // tool stderr separated from shim logs
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	defer func() {
		if cmd.Process != nil {
			// Graceful: SIGTERM first, then SIGKILL after grace period
			syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			done := make(chan struct{})
			go func() { cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(toolShutdownGrace):
				syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				<-done
			}
		}
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "aegis-proxy", Version: "0.1.0"}, nil)
	toolTransport := &mcp.CommandTransport{Command: cmd}

	toolSession, err := client.Connect(ctx, toolTransport, nil)
	if err != nil {
		logger.Error("failed to connect to tool server", "error", err)
		os.Exit(1)
	}
	defer toolSession.Close()

	toolsResult, err := toolSession.ListTools(ctx, nil)
	if err != nil {
		logger.Error("failed to list tools", "error", err)
		os.Exit(1)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "aegis-proxy", Version: "0.1.0"}, nil)

	proxyState := &proxyState{
		daemonConn:  &daemonConn,
		daemonMu:    &daemonMu,
		daemonDone:  daemonDone,
		pending:     &pending,
		localEval:   localEvaluator,
		localScorer: localScorer,
		shimID:      shimID,
		agentID:     *agentID,
		logger:      logger,
		toolSession: toolSession,
	}

	for _, tool := range toolsResult.Tools {
		registerProxyTool(server, tool, proxyState)
	}

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		logger.Error("server exited", "error", err)
	}
}

// proxyState holds shared state for all tool handlers, avoiding giant parameter lists.
type proxyState struct {
	daemonConn  *net.Conn
	daemonMu    *sync.Mutex
	daemonDone  chan struct{}
	pending     *sync.Map
	localEval   policy.PolicyEvaluator
	localScorer *risk.CompositeScorer
	shimID      string
	agentID     string
	logger      *slog.Logger
	toolSession *mcp.ClientSession
}

func registerProxyTool(server *mcp.Server, tool *mcp.Tool, ps *proxyState) {
	toolName := tool.Name

	handler := func(ctx context.Context, req *mcp.CallToolRequest) (result *mcp.CallToolResult, err error) {
		// Panic recovery — never crash the shim from a handler
		defer func() {
			if r := recover(); r != nil {
				ps.logger.Error("handler panic recovered", "tool", toolName, "panic", fmt.Sprint(r))
				result = &mcp.CallToolResult{
					IsError: true,
					Content: []mcp.Content{
						&mcp.TextContent{Text: "Aegis internal error: handler panic recovered"},
					},
				}
				err = nil
			}
		}()

		argsJSON := string(req.Params.Arguments)

		// Get daemon connection (may be nil)
		ps.daemonMu.Lock()
		conn := *ps.daemonConn
		ps.daemonMu.Unlock()

		decision := evaluate(ctx, conn, ps.daemonMu, ps.daemonDone, ps.pending,
			ps.localEval, ps.localScorer, toolName, argsJSON, ps.shimID, ps.agentID, ps.logger)

		if decision.Action == "deny" {
			ps.logger.Info("tool_denied", "tool", toolName, "policy", decision.Policy, "risk", decision.RiskScore)
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{
					&mcp.TextContent{Text: decision.DenyMessage},
				},
			}, nil
		}

		// Log allowed calls for standalone observability
		ps.logger.Info("tool_allowed", "tool", toolName, "policy", decision.Policy, "risk", decision.RiskScore)

		// Forward to real tool with timeout
		toolCtx, toolCancel := context.WithTimeout(ctx, toolExecTimeout)
		defer toolCancel()

		result, err = ps.toolSession.CallTool(toolCtx, &mcp.CallToolParams{
			Name:      toolName,
			Arguments: req.Params.Arguments,
		})
		if err != nil {
			ps.logger.Error("tool_exec_failed", "tool", toolName, "error", err)
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{
					&mcp.TextContent{Text: fmt.Sprintf("Tool error: %v", err)},
				},
			}, nil
		}
		return result, nil
	}

	server.AddTool(tool, handler)
}

func setupLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelWarn
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

func loadLocalPolicy(path string, logger *slog.Logger) policy.PolicyEvaluator {
	if path == "" {
		return policy.NewStaticEvaluator(nil, "default", policy.ActionDeny)
	}

	// Build full pipeline (OPA + extraction + DLP) for standalone mode
	cmdDBPath := filepath.Join(filepath.Dir(path), "data", "commands.yaml")
	pipeline := policy.BuildDefaultPipeline(cmdDBPath, logger)

	// Also load YAML rules as fallback
	eval, err := policy.LoadFromFile(path)
	if err != nil {
		logger.Warn("policy YAML load failed, using pipeline only", "path", path, "error", err)
		return pipeline
	}

	// Chain: Pipeline first (OPA-based), StaticEvaluator as fallback
	return policy.EvaluatorChain{pipeline, eval}
}

func createLocalScorer() *risk.CompositeScorer {
	return risk.NewCompositeScorer(
		[]risk.RiskSignal{
			risk.ToolClassificationSignal{},
			risk.ArgPatternSignal{},
			risk.RateSignal{},
		},
		map[string]float64{"tool_class": 1.0, "arg_pattern": 1.0, "rate": 1.0},
	)
}

func connectAndRegister(socketPath, shimID, agentID string, pending *sync.Map, logger *slog.Logger) (net.Conn, chan struct{}, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("dial daemon: %w", err)
	}

	env := &ipc.AegisEnvelope{
		Type:    "register",
		ShimID:  shimID,
		AgentID: agentID,
	}
	if err := ipc.WriteEnvelope(conn, env); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("send registration: %w", err)
	}

	resp, err := ipc.ReadEnvelope(conn)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("read registration response: %w", err)
	}
	if resp.Type != "registered" {
		conn.Close()
		if resp.Error != "" {
			return nil, nil, fmt.Errorf("registration rejected: %s", resp.Error)
		}
		return nil, nil, fmt.Errorf("unexpected response type: %s", resp.Type)
	}

	done := make(chan struct{})
	go readLoop(conn, pending, done, logger)

	return conn, done, nil
}

func readLoop(conn net.Conn, pending *sync.Map, done chan struct{}, logger *slog.Logger) {
	defer close(done)
	for {
		env, err := ipc.ReadEnvelope(conn)
		if err != nil {
			if err != io.EOF {
				logger.Debug("daemon read error", "error", err)
			}
			return
		}
		if ch, ok := pending.Load(env.RequestID); ok {
			ch.(chan *ipc.AegisEnvelope) <- env
		}
	}
}

func evaluate(ctx context.Context, daemonConn net.Conn, daemonMu *sync.Mutex, daemonDone chan struct{}, pending *sync.Map,
	localEval policy.PolicyEvaluator, localScorer *risk.CompositeScorer,
	toolName, argsJSON, shimID, agentID string, logger *slog.Logger) *ipc.EvaluationResult {

	if daemonConn != nil {
		result, err := evaluateViaDaemon(ctx, daemonConn, daemonMu, daemonDone, pending, toolName, argsJSON, shimID, agentID)
		if err == nil {
			return result
		}
		logger.Warn("daemon eval failed, falling back to local", "error", err)
	}

	return evaluateLocally(ctx, localEval, localScorer, toolName, argsJSON, agentID)
}

func evaluateViaDaemon(ctx context.Context, conn net.Conn, mu *sync.Mutex, done chan struct{}, pending *sync.Map,
	toolName, argsJSON, shimID, agentID string) (*ipc.EvaluationResult, error) {

	requestID := uuid.New().String()
	ch := make(chan *ipc.AegisEnvelope, 1)
	pending.Store(requestID, ch)
	defer pending.Delete(requestID)

	env := &ipc.AegisEnvelope{
		Type:       "evaluate",
		ShimID:     shimID,
		AgentID:    agentID,
		ToolName:   toolName,
		RequestID:  requestID,
		MCPMessage: json.RawMessage(argsJSON),
	}

	mu.Lock()
	err := ipc.WriteEnvelope(conn, env)
	mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("send evaluate: %w", err)
	}

	timeout := daemonEvalTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, fmt.Errorf("daemon disconnected")
		}
		if resp.Evaluation == nil {
			if resp.Error != "" {
				return nil, fmt.Errorf("daemon error: %s", resp.Error)
			}
			return nil, fmt.Errorf("empty evaluation response")
		}
		return resp.Evaluation, nil
	case <-done:
		return nil, fmt.Errorf("daemon disconnected")
	case <-ctx.Done():
		return nil, fmt.Errorf("evaluation cancelled: %w", ctx.Err())
	case <-timer.C:
		return nil, fmt.Errorf("evaluation timed out after %v", timeout)
	}
}

func evaluateLocally(ctx context.Context, localEval policy.PolicyEvaluator, scorer *risk.CompositeScorer,
	toolName, argsJSON, agentID string) *ipc.EvaluationResult {

	req := &policy.ToolCallRequest{
		AgentID:   agentID,
		Tool:      toolName,
		Arguments: argsJSON,
	}

	decision, err := localEval.Evaluate(ctx, req)
	if err != nil {
		return &ipc.EvaluationResult{
			Action:      "deny",
			Reason:      fmt.Sprintf("policy evaluation error: %v", err),
			DenyMessage: fmt.Sprintf("Policy evaluation failed: %v", err),
		}
	}

	riskScore := scorer.Score(ctx, toolName, argsJSON, 0)

	result := &ipc.EvaluationResult{
		Policy:    decision.PolicyName,
		RiskScore: riskScore,
		Reason:    decision.Reason,
	}

	switch decision.Action {
	case policy.ActionAllow:
		result.Action = "allow"
	case policy.ActionDeny:
		result.Action = "deny"
		result.DenyMessage = fmt.Sprintf("Blocked by policy %q: %s (risk=%.2f)", decision.PolicyName, decision.Reason, riskScore)
	case policy.ActionThrottle:
		result.Action = "deny"
		result.DenyMessage = fmt.Sprintf("Blocked by Aegis: rate limited (%s)", decision.Reason)
	case policy.ActionEscalateHuman:
		result.Action = "deny"
		result.DenyMessage = "Blocked by Aegis: human approval required but not available in standalone mode"
	default:
		result.Action = "deny"
		result.DenyMessage = "Blocked by Aegis: unknown policy action"
	}

	return result
}
