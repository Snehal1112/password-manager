-- Migration: Add secret expiration and activation fields
-- Description: Adds lifecycle management fields to secrets table for Azure Key Vault compatibility
-- Version: 20241026000001

-- Add expiration and activation fields to secrets table
ALTER TABLE secrets ADD COLUMN expires_at TIMESTAMP NULL;
ALTER TABLE secrets ADD COLUMN not_before TIMESTAMP NULL;
ALTER TABLE secrets ADD COLUMN enabled BOOLEAN DEFAULT TRUE;

-- Create index for expiration queries (performance optimization)
CREATE INDEX idx_secrets_expires_at ON secrets(expires_at)
WHERE deleted_at IS NULL AND expires_at IS NOT NULL;

-- Create index for enabled secrets lookup
CREATE INDEX idx_secrets_enabled ON secrets(enabled, deleted_at)
WHERE deleted_at IS NULL;

-- Comment on new columns
COMMENT ON COLUMN secrets.expires_at IS 'Timestamp when secret expires and becomes inaccessible';
COMMENT ON COLUMN secrets.not_before IS 'Timestamp before which secret cannot be accessed';
COMMENT ON COLUMN secrets.enabled IS 'Whether the secret is enabled for use';

-- Migration metadata
INSERT INTO migrations (version, description, applied_at)
VALUES ('20241026000001', 'Add secret expiration and activation fields', NOW())
ON CONFLICT (version) DO NOTHING;
