-- Migration: Remove tags column from secrets table
-- Description: Removes tags column from secrets table
-- Version: 20241026000003

-- Drop index for tags filtering first (required before dropping column)
DROP INDEX IF EXISTS idx_secrets_tags;

-- Remove tags column from secrets table
ALTER TABLE secrets DROP COLUMN tags;
