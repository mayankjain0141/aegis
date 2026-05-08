-- Phase 3A: Initial schema for the Aegis trace store.
-- Run against PostgreSQL 15+.

CREATE TABLE IF NOT EXISTS traces (
    id              UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    session_id      UUID NOT NULL,
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
    latency_ms      INTEGER,
    error_code      INTEGER,
    error           TEXT,
    metadata        JSONB
);

CREATE INDEX IF NOT EXISTS idx_traces_timestamp ON traces (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_traces_session ON traces (session_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_traces_decision ON traces (decision, timestamp) WHERE decision != 'allow';
CREATE INDEX IF NOT EXISTS idx_traces_agent ON traces (agent_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_traces_request ON traces (request_id);
