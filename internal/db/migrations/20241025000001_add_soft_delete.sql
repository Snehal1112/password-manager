-- Migration: Add soft delete and purge protection to secrets table
-- Description: Adds deleted_at timestamp and purge_protection flag for soft delete functionality

-- Add soft delete columns to secrets table
ALTER TABLE secrets ADD COLUMN deleted_at TIMESTAMP DEFAULT NULL;
ALTER TABLE secrets ADD COLUMN purge_protection BOOLEAN DEFAULT FALSE;

-- Add soft delete columns to keys table
ALTER TABLE keys ADD COLUMN deleted_at TIMESTAMP DEFAULT NULL;
ALTER TABLE keys ADD COLUMN purge_protection BOOLEAN DEFAULT FALSE;

-- Add soft delete columns to certificates table
ALTER TABLE certificates ADD COLUMN deleted_at TIMESTAMP DEFAULT NULL;
ALTER TABLE certificates ADD COLUMN purge_protection BOOLEAN DEFAULT FALSE;

-- Create indexes for soft delete queries
CREATE INDEX IF NOT EXISTS idx_secrets_deleted_at ON secrets(deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_secrets_purge_protection ON secrets(purge_protection);
CREATE INDEX IF NOT EXISTS idx_keys_deleted_at ON keys(deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_keys_purge_protection ON keys(purge_protection);
CREATE INDEX IF NOT EXISTS idx_certificates_deleted_at ON certificates(deleted_at) WHERE deleted_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_certificates_purge_protection ON certificates(purge_protection);

-- Insert migration record
INSERT INTO schema_migrations (version, description, applied_at) VALUES (1, 'Add soft delete and purge protection', CURRENT_TIMESTAMP);