# File Integrity Monitor (FIM)

The FIM module provides endpoint integrity monitoring by calculating and tracking SHA-256 hashes of critical system files (Crown Jewels) in 4KB chunks.

## Configuration
Create a `config.json` in this directory based on the provided `config.example.json`.
Only strictly necessary files should be tracked to avoid high I/O overhead (Whitelist strategy).

## Architecture
- **Storage:** Baselines and events are stored in the unified `logs/ids_database.sqlite3`.
- **Alerting:** Integrates with L0 (Local Logs) and L1 (Email Alerts for CRITICAL events like modifications or deletions).

## Known Technical Debt
1. **TOCTOU (Time-of-Check to Time-of-Use):** The polling interval leaves a blind spot between checks. Accepted for MVP.
2. **`is_active` Column:** Schema includes an `is_active` flag for soft-deletes of baselines, but the UPDATE logic is not yet implemented in the core engine.
