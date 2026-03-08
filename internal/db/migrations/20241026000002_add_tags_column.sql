-- Migration: Add tags column to secrets table
-- Description: Adds inline tags column for secret categorization.
--              Dropped by 20241026000003 which moves tags to the
--              secret_tags join table.
-- Version: 20241026000002

ALTER TABLE secrets ADD COLUMN tags TEXT DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_secrets_tags ON secrets(tags);
