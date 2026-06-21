-- Habilitar Write-Ahead Logging (persistente) para concurrencia multi-hilo
PRAGMA journal_mode=WAL;

-- Tabla principal de eventos de auditoría
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL, -- Epoch Unix time (seconds) 
    level TEXT NOT NULL,
    module_source TEXT NOT NULL,
    message TEXT NOT NULL,
    context_data TEXT
);

-- Índices para optimización de consultas SIEM
CREATE INDEX IF NOT EXISTS idx_time_level ON audit_events(timestamp, level);
CREATE INDEX IF NOT EXISTS idx_module ON audit_events(module_source, timestamp);

-- Tamper-evident sealing checkpoints (logs/integrity.py). Each row seals the
-- audit_events segment (from_id, through_id] with a hash chained to the prior
-- seal's chain_hash, so modifying or deleting a sealed event is detectable.
-- Additive-only and independent of the hot logging path.
CREATE TABLE IF NOT EXISTS audit_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,          -- Epoch Unix time (seconds)
    from_id INTEGER NOT NULL,          -- first audit_events.id covered (inclusive)
    through_id INTEGER NOT NULL,       -- last audit_events.id covered (inclusive)
    row_count INTEGER NOT NULL,        -- events folded into this segment
    chain_hash TEXT NOT NULL,          -- running hash after this segment
    prev_chain_hash TEXT NOT NULL      -- chain_hash of the previous seal (or GENESIS)
);
