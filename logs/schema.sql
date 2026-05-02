-- Habilitar Write-Ahead Logging (persistente) para concurrencia multi-hilo
PRAGMA journal_mode=WAL;

-- Tabla principal de eventos de auditoría
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    level TEXT NOT NULL,
    module_source TEXT NOT NULL,
    message TEXT NOT NULL,
    context_data TEXT
);

-- Índices para optimización de consultas SIEM
CREATE INDEX IF NOT EXISTS idx_time_level ON audit_events(timestamp, level);
CREATE INDEX IF NOT EXISTS idx_module ON audit_events(module_source, timestamp);
