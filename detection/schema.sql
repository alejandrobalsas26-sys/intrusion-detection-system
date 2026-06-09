-- Correlated incidents produced by the detection engine.
-- Additive-only: never modifies existing tables.
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,            -- Epoch Unix time (seconds)
    rule_name TEXT NOT NULL,             -- Correlation rule that fired
    title TEXT NOT NULL,
    severity TEXT NOT NULL,              -- INFO / WARNING / ERROR / CRITICAL
    risk_score INTEGER NOT NULL,         -- 0-100
    mitre_techniques TEXT,               -- JSON array of ATT&CK technique IDs
    entities TEXT,                       -- JSON array of involved entities (IPs, users, paths)
    event_count INTEGER NOT NULL DEFAULT 1,
    first_event_ts REAL,
    last_event_ts REAL,
    summary TEXT,
    status TEXT NOT NULL DEFAULT 'open', -- open / acknowledged / closed
    dedupe_key TEXT UNIQUE               -- prevents duplicate incidents across sweeps
);

CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, created_at);
