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
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/mayjain/aegis/internal/ipc"
	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/internal/risk"
	"github.com/modelcontextprotocol/go-sdk/mcp"
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

	cmd := exec.Command(toolCmd[0], toolCmd[1:]...)
	cmd.Stderr = os.Stderr
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
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

	server := mcp.NewServer(&mcp.Implementation{Name: "aegis-proxy", Version: "0.1.0"}, &mcp.ServerOptions{
		Logger: logger,
	})

	for _, tool := range toolsResult.Tools {
		registerProxyTool(server, tool, toolSession, &daemonConn, &daemonMu, daemonDone, &pending, localEvaluator, localScorer, shimID, *agentID, logger)
	}

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
}

func registerProxyTool(server *mcp.Server, tool *mcp.Tool, toolSession *mcp.ClientSession,
	daemonConn *net.Conn, daemonMu *sync.Mutex, daemonDone chan struct{}, pending *sync.Map,
	localEval policy.PolicyEvaluator, localScorer *risk.CompositeScorer,
	shimID, agentID string, logger *slog.Logger) {

	toolName := tool.Name

	handler := func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		argsJSON := string(req.Params.Arguments)

		daemonMu.Lock()
		conn := *daemonConn
		daemonMu.Unlock()

		decision := evaluate(ctx, conn, daemonMu, daemonDone, pending, localEval, localScorer, toolName, argsJSON, shimID, agentID, logger)

		if decision.Action == "deny" {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{
					&mcp.TextContent{Text: decision.DenyMessage},
				},
			}, nil
		}

		result, err := toolSession.CallTool(ctx, &mcp.CallToolParams{
			Name:      toolName,
			Arguments: req.Params.Arguments,
		})
		if err != nil {
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
		rules := []policy.CompiledRule{}
		return policy.NewStaticEvaluator(rules, "default", policy.ActionDeny)
	}
	eval, err := policy.LoadFromFile(path)
	if err != nil {
		logger.Error("failed to load policy, using default-deny", "path", path, "error", err)
		rules := []policy.CompiledRule{}
		return policy.NewStaticEvaluator(rules, "default", policy.ActionDeny)
	}
	return eval
}

func createLocalScorer() *risk.CompositeScorer {
	signals := []risk.RiskSignal{
		risk.ToolClassificationSignal{},
		risk.ArgPatternSignal{},
		risk.RateSignal{},
	}
	weights := map[string]float64{
		"tool_class":  1.0,
		"arg_pattern": 1.0,
		"rate":        1.0,
	}
	return risk.NewCompositeScorer(signals, weights)
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

	return evaluateLocally(localEval, localScorer, toolName, argsJSON, agentID)
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

	timeout := 30 * time.Second
	deadline, ok := ctx.Deadline()
	if ok && time.Until(deadline) < timeout {
		timeout = time.Until(deadline)
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

func evaluateLocally(localEval policy.PolicyEvaluator, scorer *risk.CompositeScorer,
	toolName, argsJSON, agentID string) *ipc.EvaluationResult {

	req := &policy.ToolCallRequest{
		AgentID:   agentID,
		Tool:      toolName,
		Arguments: argsJSON,
	}

	decision, err := localEval.Evaluate(context.Background(), req)
	if err != nil {
		return &ipc.EvaluationResult{
			Action:      "deny",
			Reason:      fmt.Sprintf("policy evaluation error: %v", err),
			DenyMessage: fmt.Sprintf("Policy evaluation failed: %v", err),
		}
	}

	riskScore := scorer.Score(context.Background(), toolName, argsJSON, 0)

	result := &ipc.EvaluationResult{
		Action:    string(decision.Action),
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
