package trace

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultChannelSize  = 4096
	defaultBatchSize    = 64
	defaultFlushInterval = 100 * time.Millisecond
)


// BatchCollector buffers TraceEvents and writes them in batches to PostgreSQL.
// If no PG connection is available, events are logged to stderr.
type BatchCollector struct {
	ch            chan *TraceEvent
	db            *pgxpool.Pool
	wal           *WALWriter
	logger        *slog.Logger
	dropped       atomic.Int64
	written       atomic.Int64
	batchSize     int
	flushInterval time.Duration
	done          chan struct{}
	closeOnce     sync.Once

	// flushMu serializes flush operations
	flushMu sync.Mutex
	// pending holds events between flushes (guarded by flushMu)
	pending []*TraceEvent
	// flushed is signaled after each flush for testing
	flushed chan struct{}
}

func NewBatchCollector(db *pgxpool.Pool, logger *slog.Logger) *BatchCollector {
	return newBatchCollector(db, logger, defaultChannelSize, defaultBatchSize, defaultFlushInterval)
}

func newBatchCollector(db *pgxpool.Pool, logger *slog.Logger, chanSize, batchSize int, flushInterval time.Duration) *BatchCollector {
	bc := &BatchCollector{
		ch:            make(chan *TraceEvent, chanSize),
		db:            db,
		logger:        logger,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		done:          make(chan struct{}),
		pending:       make([]*TraceEvent, 0, batchSize),
		flushed:       make(chan struct{}, 1),
	}
	go bc.loop()
	return bc
}

// Emit sends a TraceEvent to the collector. Non-blocking: drops the event if
// the internal channel is full.
func (bc *BatchCollector) Emit(event *TraceEvent) {
	select {
	case bc.ch <- event:
	default:
		bc.dropped.Add(1)
	}
}

// Flush forces an immediate flush of pending events.
func (bc *BatchCollector) Flush() error {
	bc.flushMu.Lock()
	defer bc.flushMu.Unlock()
	return bc.flushLocked()
}

// Close stops the background loop, drains remaining events, and flushes.
func (bc *BatchCollector) Close() error {
	var err error
	bc.closeOnce.Do(func() {
		close(bc.ch)
		<-bc.done
		err = bc.Flush()
	})
	return err
}

// Stats returns the number of successfully written and dropped events.
func (bc *BatchCollector) Stats() (written, dropped int64) {
	return bc.written.Load(), bc.dropped.Load()
}

func (bc *BatchCollector) loop() {
	defer close(bc.done)
	ticker := time.NewTicker(bc.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case ev, ok := <-bc.ch:
			if !ok {
				// channel closed — drain remaining
				bc.drainChannel()
				return
			}
			bc.flushMu.Lock()
			bc.pending = append(bc.pending, ev)
			if len(bc.pending) >= bc.batchSize {
				_ = bc.flushLocked()
			}
			bc.flushMu.Unlock()

		case <-ticker.C:
			bc.flushMu.Lock()
			if len(bc.pending) > 0 {
				_ = bc.flushLocked()
			}
			bc.flushMu.Unlock()
		}
	}
}

func (bc *BatchCollector) drainChannel() {
	bc.flushMu.Lock()
	defer bc.flushMu.Unlock()
	for ev := range bc.ch {
		bc.pending = append(bc.pending, ev)
	}
	_ = bc.flushLocked()
}

// SetWAL attaches a WAL writer to the collector for PG-failure fallback.
func (bc *BatchCollector) SetWAL(w *WALWriter) {
	bc.wal = w
}

// flushLocked writes pending events to PG (or logs them). Caller must hold flushMu.
// If PG write fails and a WAL is configured, events are written to WAL instead.
func (bc *BatchCollector) flushLocked() error {
	if len(bc.pending) == 0 {
		return nil
	}

	batch := bc.pending
	bc.pending = make([]*TraceEvent, 0, bc.batchSize)

	var err error
	if bc.db != nil {
		err = bc.writeToPG(batch)
		if err != nil && bc.wal != nil {
			bc.logger.Warn("pg write failed, falling back to WAL", "error", err, "events", len(batch))
			for _, ev := range batch {
				if walErr := bc.wal.Write(ev); walErr != nil {
					bc.logger.Error("wal write failed", "error", walErr)
				}
			}
		}
	} else {
		bc.writeToLog(batch)
	}

	if err == nil {
		bc.written.Add(int64(len(batch)))
	}

	// non-blocking signal for tests
	select {
	case bc.flushed <- struct{}{}:
	default:
	}

	return err
}

func (bc *BatchCollector) writeToPG(batch []*TraceEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := bc.db.Begin(ctx)
	if err != nil {
		bc.logger.Error("pg begin tx failed", "error", err)
		return err
	}
	defer tx.Rollback(ctx)

	const insertSQL = `INSERT INTO traces (
		session_id, request_id, agent_id, timestamp, tool,
		args_hash, args_summary, risk_score, decision,
		policy_id, policy_version, mode, latency_us,
		error_code, error, metadata
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`

	for _, ev := range batch {
		var errCode *int
		if ev.ErrorCode != nil {
			errCode = ev.ErrorCode
		}
		sessionID := nilIfEmpty(ev.SessionID)
		_, err := tx.Exec(ctx, insertSQL,
			sessionID, ev.RequestID, ev.AgentID, ev.Timestamp, ev.Tool,
			ev.ArgsHash, ev.ArgsSummary, ev.RiskScore, ev.Decision,
			ev.PolicyID, ev.PolicyVersion, ev.Mode, ev.LatencyUs,
			errCode, nilIfEmpty(ev.Error), nil,
		)
		if err != nil {
			bc.logger.Error("pg insert failed", "error", err)
			return err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		bc.logger.Error("pg commit failed", "error", err)
		return err
	}
	return nil
}

func (bc *BatchCollector) writeToLog(batch []*TraceEvent) {
	for _, ev := range batch {
		bc.logger.Info("trace_event",
			"session_id", ev.SessionID,
			"request_id", ev.RequestID,
			"agent_id", ev.AgentID,
			"tool", ev.Tool,
			"risk_score", fmt.Sprintf("%.2f", ev.RiskScore),
			"decision", ev.Decision,
			"latency_us", ev.LatencyUs,
		)
	}
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
