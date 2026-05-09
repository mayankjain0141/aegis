package trace

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CreateSchema is the SQL DDL for the traces table and its indexes.
const CreateSchema = `
CREATE TABLE IF NOT EXISTS traces (
    id              UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    session_id      UUID,
    request_id      TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT now(),
    tool            TEXT NOT NULL,
    args_hash       TEXT,
    args_summary    TEXT,
    risk_score      REAL NOT NULL,
    decision        TEXT NOT NULL,
    policy_id       TEXT,
    policy_version  TEXT,
    mode            TEXT NOT NULL DEFAULT 'enforce',
    latency_us      INTEGER,
    error_code      INTEGER,
    error           TEXT,
    metadata        JSONB
);

CREATE INDEX IF NOT EXISTS idx_traces_timestamp ON traces (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_traces_session ON traces (session_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_traces_decision ON traces (decision, timestamp) WHERE decision != 'allow';
CREATE INDEX IF NOT EXISTS idx_traces_agent ON traces (agent_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_traces_request ON traces (request_id);
`

// RunMigrations executes the schema creation DDL against the given pool.
func RunMigrations(ctx context.Context, db *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err := db.Exec(ctx, CreateSchema)
	return err
}
