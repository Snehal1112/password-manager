-- Migration: Remove tags functionality completely
-- Description: Drops tags column and associated index to fully remove tags feature
-- Version: 20241026000005

-- Drop index for tags filtering first (required before dropping column)
DROP INDEX IF EXISTS idx_secrets_tags;

-- Remove tags column from secrets table
ALTER TABLE secrets DROP COLUMN tags;