-- Migration: Add tags column to secrets table
-- Description: Adds tags column for secret categorization and filtering
-- Version: 20241026000004

-- Add tags column to secrets table
ALTER TABLE secrets ADD COLUMN tags TEXT DEFAULT '';

-- Create index for tags filtering
CREATE INDEX IF NOT EXISTS idx_secrets_tags ON secrets(tags);
