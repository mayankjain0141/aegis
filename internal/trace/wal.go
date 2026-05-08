package trace

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const defaultMaxWALSize = 100 * 1024 * 1024 // 100MB

// WALWriter provides an append-only local file fallback for trace events when
// PostgreSQL is unreachable. Events are written as newline-delimited JSON.
type WALWriter struct {
	path    string
	file    *os.File
	mu      sync.Mutex
	size    int64
	maxSize int64
	logger  *slog.Logger
}

func NewWALWriter(path string, logger *slog.Logger) (*WALWriter, error) {
	return NewWALWriterWithSize(path, defaultMaxWALSize, logger)
}

func NewWALWriterWithSize(path string, maxSize int64, logger *slog.Logger) (*WALWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("wal open: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("wal stat: %w", err)
	}
	return &WALWriter{
		path:    path,
		file:    f,
		size:    info.Size(),
		maxSize: maxSize,
		logger:  logger,
	}, nil
}

// Write appends a single TraceEvent as a JSON line.
func (w *WALWriter) Write(event *TraceEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("wal marshal: %w", err)
	}
	data = append(data, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.size+int64(len(data)) > w.maxSize {
		if err := w.rotateLocked(); err != nil {
			return fmt.Errorf("wal rotate: %w", err)
		}
	}

	n, err := w.file.Write(data)
	if err != nil {
		return fmt.Errorf("wal write: %w", err)
	}
	w.size += int64(n)
	return nil
}

// Replay reads all WAL lines and inserts them into PostgreSQL.
// Corrupt/unparseable lines are skipped with a warning log.
// Returns the number of successfully replayed events.
func (w *WALWriter) Replay(ctx context.Context, db *pgxpool.Pool) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Sync and reopen for reading
	if err := w.file.Sync(); err != nil {
		return 0, fmt.Errorf("wal sync: %w", err)
	}

	rf, err := os.Open(w.path)
	if err != nil {
		return 0, fmt.Errorf("wal open for replay: %w", err)
	}
	defer rf.Close()

	const insertSQL = `INSERT INTO traces (
		session_id, request_id, agent_id, timestamp, tool,
		args_hash, args_summary, risk_score, decision,
		policy_id, policy_version, mode, latency_ms,
		error_code, error, metadata
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`

	scanner := bufio.NewScanner(rf)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	count := 0
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var ev TraceEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			w.logger.Warn("wal replay: corrupt line skipped", "line", lineNum, "error", err)
			continue
		}

		_, err := db.Exec(ctx, insertSQL,
			ev.SessionID, ev.RequestID, ev.AgentID, ev.Timestamp, ev.Tool,
			ev.ArgsHash, ev.ArgsSummary, ev.RiskScore, ev.Decision,
			ev.PolicyID, ev.PolicyVersion, ev.Mode, ev.LatencyMs,
			ev.ErrorCode, nilIfEmpty(ev.Error), nil,
		)
		if err != nil {
			return count, fmt.Errorf("wal replay insert at line %d: %w", lineNum, err)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("wal replay scan: %w", err)
	}
	return count, nil
}

// Truncate clears the WAL file after a successful replay.
func (w *WALWriter) Truncate() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.file.Close(); err != nil {
		return fmt.Errorf("wal close for truncate: %w", err)
	}

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("wal truncate open: %w", err)
	}
	w.file = f
	w.size = 0
	return nil
}

// Close syncs and closes the WAL file.
func (w *WALWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

// Size returns the current WAL file size in bytes.
func (w *WALWriter) Size() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.size
}

func (w *WALWriter) rotateLocked() error {
	if err := w.file.Close(); err != nil {
		return err
	}

	backupPath := w.path + ".1"
	_ = os.Remove(backupPath)
	if err := os.Rename(w.path, backupPath); err != nil {
		return err
	}

	w.logger.Info("wal rotated", "backup", backupPath, "previous_size", w.size)

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	w.file = f
	w.size = 0
	return nil
}

// replayEvent is used to expose replay insertion for testing without needing PG.
// Keeping it in the main file so tests in the same package can use it.
func parseWALLine(line []byte) (*TraceEvent, error) {
	var ev TraceEvent
	if err := json.Unmarshal(line, &ev); err != nil {
		return nil, err
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	return &ev, nil
}
