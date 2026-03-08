-- Migration: Add per-operation access policies table
-- Description: Stores explicit allow/deny decisions for (principal, resource_type, operation).
--              Checked before RBAC; explicit deny always wins.
-- Version: 20260308000002

CREATE TABLE IF NOT EXISTS access_policies (
    id             TEXT PRIMARY KEY,
    principal_id   TEXT NOT NULL,
    principal_type TEXT NOT NULL CHECK(principal_type IN ('user','service_account')),
    resource_type  TEXT NOT NULL CHECK(resource_type IN ('secrets','keys','certificates')),
    operation      TEXT NOT NULL,
    effect         TEXT NOT NULL CHECK(effect IN ('allow','deny')),
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_access_policies_principal ON access_policies(principal_id);
CREATE INDEX IF NOT EXISTS idx_access_policies_lookup    ON access_policies(principal_id, resource_type, operation);
