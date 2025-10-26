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
CREATE INDEX IF NOT EXISTS idx_secrets_enabled ON secrets(enabled, deleted_at)
WHERE deleted_at IS NULL;
