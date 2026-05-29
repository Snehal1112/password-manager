-- Create the vaults table.
CREATE TABLE IF NOT EXISTS vaults (
    id                 TEXT PRIMARY KEY,
    name               TEXT UNIQUE NOT NULL,
    enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    purge_protection   BOOLEAN NOT NULL DEFAULT FALSE,
    retention_days     INTEGER NOT NULL DEFAULT 90,
    created_by         TEXT NOT NULL,
    created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at         TIMESTAMP NULL,
    scheduled_purge_at TIMESTAMP NULL
);
CREATE INDEX IF NOT EXISTS idx_vaults_name ON vaults(name);

-- Seed the default vault with the fixed well-known UUID, owned by any existing admin.
INSERT INTO vaults (id, name, enabled, retention_days, created_by)
SELECT '00000000-0000-0000-0000-00000000efa1', 'default', 1, 90,
       COALESCE((SELECT id FROM users WHERE role = 'admin' LIMIT 1),
                (SELECT id FROM users LIMIT 1),
                '00000000-0000-0000-0000-000000000000')
WHERE NOT EXISTS (SELECT 1 FROM vaults WHERE name = 'default');

-- Add vault_id to resource tables, defaulting existing rows to the default vault.
ALTER TABLE secrets      ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1';
ALTER TABLE keys         ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1';
ALTER TABLE certificates ADD COLUMN vault_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1';

-- Backfill guards older SQLite behavior where the default is not retro-applied.
UPDATE secrets      SET vault_id = '00000000-0000-0000-0000-00000000efa1' WHERE vault_id IS NULL OR vault_id = '';
UPDATE keys         SET vault_id = '00000000-0000-0000-0000-00000000efa1' WHERE vault_id IS NULL OR vault_id = '';
UPDATE certificates SET vault_id = '00000000-0000-0000-0000-00000000efa1' WHERE vault_id IS NULL OR vault_id = '';

-- Add vault scoping to access policies (NULL means a global, all-vaults policy).
ALTER TABLE access_policies ADD COLUMN vault_id TEXT NULL;
