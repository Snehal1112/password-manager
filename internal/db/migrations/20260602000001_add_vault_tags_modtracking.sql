-- Vault tags (JSON key/value map) and modification tracking (Azure Key Vault parity).
ALTER TABLE vaults ADD COLUMN tags TEXT NOT NULL DEFAULT '{}';
ALTER TABLE vaults ADD COLUMN updated_at TIMESTAMP NULL;
ALTER TABLE vaults ADD COLUMN updated_by TEXT NULL;
