-- Identity Storage
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    encrypted_secret TEXT NOT NULL, -- TOTP Secret (Fernet encrypted)
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
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_replay_protection ON auth_attempts(user_id, token_fingerprint);

-- Token Blacklist
CREATE TABLE IF NOT EXISTS token_blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    reason TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
