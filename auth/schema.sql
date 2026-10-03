-- Identity Storage
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    encrypted_secret TEXT NOT NULL, -- TOTP Secret (Fernet encrypted)
    is_active INTEGER DEFAULT 1,
    role TEXT DEFAULT 'analyst',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);


-- Recovery Management
CREATE TABLE IF NOT EXISTS recovery_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    hashed_code TEXT NOT NULL, -- Scrypt hashed
    salt BLOB NOT NULL,        -- Per-code unique salt
    used_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Brute Force & Replay Protection
CREATE TABLE IF NOT EXISTS auth_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL,
    ip_address TEXT,
    token_fingerprint TEXT NOT NULL, -- Cryptographic fingerprint of the token
    totp_step INTEGER,               -- NULL for recovery, failures, and legacy rows
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Numeric TOTP values repeat in different intervals. Keep telemetry searchable,
-- but enforce single use on the verified interval instead of the digits.
DROP INDEX IF EXISTS idx_replay_protection;
CREATE INDEX IF NOT EXISTS idx_auth_fingerprint ON auth_attempts(user_id, token_fingerprint);
CREATE TABLE IF NOT EXISTS totp_consumptions (
    user_id INTEGER NOT NULL,
    time_step INTEGER NOT NULL,
    consumed_at REAL NOT NULL,
    PRIMARY KEY (user_id, time_step),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Backoff and 90s replay-window lookups filter by user_id + recent timestamp
-- (and success). This covering index keeps those reads off a full table scan
-- as auth_attempts grows. Additive and idempotent (IF NOT EXISTS).
CREATE INDEX IF NOT EXISTS idx_auth_attempts_user_time ON auth_attempts(user_id, timestamp, success);

-- NOTE: a token_blacklist table previously lived here but was never read or
-- written by any code path (TOTP replay protection uses totp_consumptions). It was removed to drop dead schema.
-- Existing databases keep their empty table harmlessly; new ones simply omit it.
