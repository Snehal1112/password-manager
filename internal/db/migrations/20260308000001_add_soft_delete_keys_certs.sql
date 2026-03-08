-- Migration: Add soft-delete columns to keys and certificates tables
-- Description: Mirrors the soft-delete pattern already on the secrets table.
--              Adds deleted_at, purge_protection, and scheduled_purge_at to keys
--              and certificates so they support AKV-style soft-delete.
--              Note: deleted_at and purge_protection were already added by
--              migration 20241025000001. This migration adds scheduled_purge_at only.
-- Version: 20260308000001

ALTER TABLE keys ADD COLUMN scheduled_purge_at TIMESTAMP DEFAULT NULL;

ALTER TABLE certificates ADD COLUMN scheduled_purge_at TIMESTAMP DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_keys_scheduled_purge_at ON keys(scheduled_purge_at) WHERE scheduled_purge_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_certificates_scheduled_purge_at ON certificates(scheduled_purge_at) WHERE scheduled_purge_at IS NOT NULL;
