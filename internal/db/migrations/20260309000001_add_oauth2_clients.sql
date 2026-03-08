-- Migration: Add OAuth2 client credentials table for service accounts
-- Description: Stores machine-to-machine authentication clients (RFC 6749 §4.4).
--              client_secret is bcrypt-hashed; raw secret is returned only once.
-- Version: 20260309000001

CREATE TABLE IF NOT EXISTS oauth2_clients (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    client_secret TEXT NOT NULL,
    description   TEXT DEFAULT '',
    enabled       BOOLEAN DEFAULT TRUE,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at    TIMESTAMP NULL
);
CREATE INDEX IF NOT EXISTS idx_oauth2_clients_name ON oauth2_clients(name);
