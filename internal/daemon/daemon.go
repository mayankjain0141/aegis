package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mayjain/aegis/internal/approval"
	"github.com/mayjain/aegis/internal/ipc"
	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/internal/risk"
	"github.com/mayjain/aegis/internal/trace"
	"github.com/mayjain/aegis/internal/ws"
)

type Daemon struct {
	router     *Router
	collector  *trace.BatchCollector
	listener   net.Listener
	socketPath string
	pgURL      string
	db         *pgxpool.Pool
	logger     *slog.Logger
	wg         sync.WaitGroup

	hub        *ws.Hub
	httpServer *http.Server
	httpPort   int
	metrics    Metrics
	startTime  time.Time
}

func New(socketPath string, configPath string, logger *slog.Logger) *Daemon {
	return NewWithPolicy(socketPath, configPath, "policies/default.yaml", logger)
}

func NewWithPolicy(socketPath string, configPath string, policyPath string, logger *slog.Logger) *Daemon {
	return NewWithOptions(socketPath, configPath, policyPath, "", logger)
}

func NewWithHTTP(socketPath, configPath, policyPath, pgURL string, httpPort int, logger *slog.Logger) *Daemon {
	d := NewWithOptions(socketPath, configPath, policyPath, pgURL, logger)
	d.httpPort = httpPort
	return d
}

func NewWithOptions(socketPath, configPath, policyPath, pgURL string, logger *slog.Logger) *Daemon {
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

	var db *pgxpool.Pool
	if pgURL != "" {
		pool, err := pgxpool.New(context.Background(), pgURL)
		if err != nil {
			logger.Error("pg connect failed, running in no-PG mode", "error", err)
		} else {
			if err := pool.Ping(context.Background()); err != nil {
				logger.Error("pg ping failed, running in no-PG mode", "error", err)
				pool.Close()
			} else {
				if err := trace.RunMigrations(context.Background(), pool); err != nil {
					logger.Error("pg migrations failed", "error", err)
					pool.Close()
				} else {
					db = pool
					logger.Info("pg connected and migrated", "url", pgURL)
				}
			}
		}
	}

	collector := trace.NewBatchCollector(db, logger)
	router := NewRouter(executor, policyEval, scorer, logger)
	router.SetCollector(collector)

	hub := ws.NewHub()

	approvalGate := approval.NewGate(hub.Broadcast, 5*time.Minute, logger)
	router.SetApprovalGate(approvalGate)

	d := &Daemon{
		router:     router,
		collector:  collector,
		socketPath: socketPath,
		pgURL:      pgURL,
		db:         db,
		logger:     logger,
		hub:        hub,
		startTime:  time.Now(),
	}

	router.SetOnTrace(func(data []byte) {
		d.hub.Broadcast(data)
	})

	return d
}

// PGConnected reports whether the daemon has an active PostgreSQL connection.
func (d *Daemon) PGConnected() bool {
	return d.db != nil
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

	// Start WebSocket hub
	hubCtx, hubCancel := context.WithCancel(ctx)
	go d.hub.Run(hubCtx)

	// Start HTTP server if port is configured
	if d.httpPort > 0 {
		addr := fmt.Sprintf(":%d", d.httpPort)
		if err := d.startHTTP(ctx, addr); err != nil {
			hubCancel()
			return err
		}
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
			default:
				d.logger.Error("accept failed", "error", err)
			}
			break
		}
		d.wg.Add(1)
		go d.handleConn(ctx, conn)
	}

	hubCancel()
	<-d.hub.Done()
	d.drainConnections()
	os.Remove(d.socketPath)
	d.logger.Info("daemon stopped")
	return nil
}

func (d *Daemon) Shutdown() error {
	if d.collector != nil {
		_ = d.collector.Close()
	}
	if d.db != nil {
		d.db.Close()
	}
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
