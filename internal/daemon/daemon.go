package daemon

import (
	"context"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mayjain/aegis/internal/ipc"
	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/internal/risk"
)

type Daemon struct {
	router     *Router
	listener   net.Listener
	socketPath string
	logger     *slog.Logger
	wg         sync.WaitGroup
}

func New(socketPath string, configPath string, logger *slog.Logger) *Daemon {
	return NewWithPolicy(socketPath, configPath, "policies/default.yaml", logger)
}

func NewWithPolicy(socketPath string, configPath string, policyPath string, logger *slog.Logger) *Daemon {
	tools, err := LoadToolsConfig(configPath)
	if err != nil {
		logger.Warn("failed to load tools config, using empty config", "path", configPath, "error", err)
		tools = map[string]ToolConfig{}
	}
	logger.Info("loaded tools config", "path", configPath, "tools", len(tools))

	executor := NewExecutor(tools, logger)

	var policyEval policy.PolicyEvaluator
	if policyPath != "" {
		eval, err := policy.LoadFromFile(policyPath)
		if err != nil {
			logger.Warn("failed to load policy file, using default-deny", "path", policyPath, "error", err)
			eval = policy.NewStaticEvaluator(nil, "fallback", policy.ActionDeny)
		} else {
			logger.Info("loaded policy", "path", policyPath, "version", eval.Version(), "rules", eval.RuleCount())
		}
		reloader := policy.NewHotReloader(eval)
		policyEval = reloader

		go func() {
			_ = policy.WatchAndReload(context.Background(), policyPath, reloader, logger)
		}()
	} else {
		policyEval = policy.NewStaticEvaluator(nil, "empty", policy.ActionDeny)
	}

	scorer := risk.NewCompositeScorer(
		[]risk.RiskSignal{
			risk.ToolClassificationSignal{},
			risk.ArgPatternSignal{},
			risk.RateSignal{},
		},
		map[string]float64{
			"tool_class":  1.0,
			"arg_pattern": 1.0,
			"rate":        1.0,
		},
	)

	return &Daemon{
		router:     NewRouter(executor, policyEval, scorer, logger),
		socketPath: socketPath,
		logger:     logger,
	}
}

func (d *Daemon) Router() *Router {
	return d.router
}

// Run starts accepting connections and blocks until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	os.Remove(d.socketPath)

	var err error
	d.listener, err = net.Listen("unix", d.socketPath)
	if err != nil {
		return err
	}

	d.logger.Info("daemon started", "socket", d.socketPath)

	go func() {
		<-ctx.Done()
		d.listener.Close()
	}()

	for {
		conn, err := d.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				// Expected shutdown
			default:
				d.logger.Error("accept failed", "error", err)
			}
			break
		}
		d.wg.Add(1)
		go d.handleConn(ctx, conn)
	}

	d.drainConnections()
	os.Remove(d.socketPath)
	d.logger.Info("daemon stopped")
	return nil
}

func (d *Daemon) Shutdown() error {
	if d.listener != nil {
		return d.listener.Close()
	}
	return nil
}

func (d *Daemon) handleConn(ctx context.Context, conn net.Conn) {
	defer d.wg.Done()
	defer conn.Close()

	d.logger.Debug("connection accepted", "remote", conn.RemoteAddr())

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		env, err := ipc.ReadEnvelope(conn)
		if err != nil {
			d.logger.Debug("connection closed", "error", err)
			return
		}

		resp, err := d.router.HandleEnvelope(conn, env)
		if err != nil {
			d.logger.Error("handler error", "error", err)
			resp = &ipc.AegisEnvelope{
				Type:  "error",
				Error: err.Error(),
			}
		}

		if err := ipc.WriteEnvelope(conn, resp); err != nil {
			d.logger.Error("write failed", "error", err)
			return
		}
	}
}

func (d *Daemon) drainConnections() {
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		d.logger.Warn("drain timeout: some connections did not close within 10s")
	}
}
