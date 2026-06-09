# L0 Module: Audit Logs (SQLite)

Core module of the IDS responsible for forensic persistence. Designed to ensure immutable event traceability, operating autonomously and idempotently without requiring manual configuration of external databases.

## Bootstrap Behavior

The module features an idempotent `_bootstrap_db()` mechanism. Upon importing `logger.py` for the first time, the system checks for the existence of the directory and the database schema. If they do not exist, it creates them automatically.
*Note: SQLite operates in WAL (Write-Ahead Logging) mode to improve concurrency and crash-safety. It is normal to observe `.sqlite3-wal` and `.sqlite3-shm` temporary files alongside the main database.*

## Schema Reference

The `audit_events` structure was designed as a navigable audit trail:

| Column | Type | Constraint | Description |
| :--- | :--- | :--- | :--- |
| `id` | INTEGER | PRIMARY KEY | Unique event identifier. |
| `timestamp` | REAL | NOT NULL | Epoch timestamp (seconds). |
| `level` | TEXT | NOT NULL | Severity: INFO, WARNING, ERROR, CRITICAL. |
| `module_source` | TEXT | NOT NULL | Originating module (e.g., 'auth', 'network'). |
| `message` | TEXT | NOT NULL | Human-readable event description. |
| `context_data` | TEXT | | (Optional) Forensic metadata in JSON format. |

## Environment Variables

* `DB_PATH`: (Optional) Absolute or relative path for the database file.
    * *Default*: `logs/ids_database.sqlite3`
* `FAILSAFE_LOG_PATH`: (Optional) Absolute or relative path for the text-based fallback log file.
    * *Default*: `logs/ids_failsafe.log`

## Forensic Query Examples

The database is optimized for Threat Hunting and Incident Response. Useful SQL queries for the SOC:

**1. Search for recent critical events (last 24 hours):**
```sql
SELECT datetime(timestamp, 'unixepoch', 'localtime') as local_time, module_source, message
FROM audit_events
WHERE level = 'CRITICAL' AND timestamp >= (unixepoch() - 86400)
ORDER BY timestamp DESC;
