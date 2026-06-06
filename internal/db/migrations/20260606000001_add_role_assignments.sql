-- Vault-scoped role assignments. Links a tenant-global principal to a role within a vault.
ALTER TABLE access_policies ADD COLUMN assignment_id TEXT NULL;

CREATE TABLE IF NOT EXISTS role_assignments (
    id             TEXT PRIMARY KEY,
    principal_id   TEXT NOT NULL,
    principal_type TEXT NOT NULL,
    role           TEXT NOT NULL,
    vault_id       TEXT NOT NULL,
    created_by     TEXT NOT NULL,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (principal_id, role, vault_id),
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_role_assignments_vault ON role_assignments(vault_id);
CREATE INDEX IF NOT EXISTS idx_access_policies_assignment ON access_policies(assignment_id);
