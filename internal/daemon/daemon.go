package daemon

import (
	"context"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mayjain/aegis/internal/ipc"
)

type Daemon struct {
	router     *Router
	listener   net.Listener
	socketPath string
	logger     *slog.Logger
	wg         sync.WaitGroup
}

func New(socketPath string, configPath string, logger *slog.Logger) *Daemon {
	tools, err := LoadToolsConfig(configPath)
	if err != nil {
		logger.Warn("failed to load tools config, using empty config", "path", configPath, "error", err)
		tools = map[string]ToolConfig{}
	}
	logger.Info("loaded tools config", "path", configPath, "tools", len(tools))

	executor := NewExecutor(tools, logger)
	return &Daemon{
		router:     NewRouter(executor, logger),
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
