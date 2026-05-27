# RocketVault Azure Key Vault Parity Audit Checklist

**Date:** 2026-05-23  
**Status:** Working checklist  
**Purpose:** Use this checklist to run a complete parity audit and capture evidence for each Azure Key Vault capability.

## 1. Define the audit scope

- [ ] Confirm whether the audit covers only Azure Key Vault data-plane features or also management-plane features.
- [ ] Confirm whether Azure Managed HSM is in scope or excluded.
- [ ] Confirm the RocketVault branch, commit, or release being audited.
- [ ] Record the version of Azure documentation being used as the reference.

## 2. Collect reference material

- [ ] Gather official Microsoft docs for secrets.
- [ ] Gather official Microsoft docs for keys.
- [ ] Gather official Microsoft docs for certificates.
- [ ] Gather official Microsoft docs for access control, soft-delete, and purge protection.
- [ ] Gather official Microsoft docs for networking, quotas, and limits.
- [ ] Record the URLs in the audit template.

## 3. Inventory RocketVault features

- [ ] Identify the RocketVault API routes for secrets.
- [ ] Identify the RocketVault API routes for keys.
- [ ] Identify the RocketVault API routes for certificates.
- [ ] Identify any auth, RBAC, OAuth2, or service account flows.
- [ ] Identify soft-delete, recovery, and purge code paths.
- [ ] Identify networking or IP allowlist code paths.
- [ ] Identify observability and audit logging code paths.
- [ ] Identify backup and restore code paths.

## 4. Audit secrets parity

- [ ] Verify create, read, update, delete, list, and version behavior.
- [ ] Verify tags, name validation, and metadata handling.
- [ ] Verify content type support.
- [ ] Verify expiry and lifecycle fields.
- [ ] Verify soft-delete and purge protection behavior.
- [ ] Verify backup and restore behavior.
- [ ] Verify secret size and tag limits.
- [ ] Verify error codes and status codes for invalid inputs.

## 5. Audit keys parity

- [ ] Verify key creation and import behavior.
- [ ] Verify key versions and listing behavior.
- [ ] Verify sign and verify operations.
- [ ] Verify encrypt and decrypt operations.
- [ ] Verify wrap and unwrap operations.
- [ ] Verify algorithm support and validation.
- [ ] Verify key deletion, recovery, and purge behavior.
- [ ] Verify key rotation behavior.
- [ ] Verify soft-delete and purge protection behavior.

## 6. Audit certificates parity

- [ ] Verify certificate creation and import behavior.
- [ ] Verify certificate listing and retrieval behavior.
- [ ] Verify certificate versioning behavior.
- [ ] Verify certificate policy support.
- [ ] Verify certificate contacts and issuer behavior.
- [ ] Verify renewal behavior and scheduler behavior, if implemented.
- [ ] Verify recovery and purge behavior.
- [ ] Verify private key handling and export behavior.

## 7. Audit authentication and access control

- [ ] Verify user authentication flows.
- [ ] Verify service account or OAuth2 client credentials flows.
- [ ] Verify RBAC or access policy enforcement.
- [ ] Verify per-operation authorization, if supported.
- [ ] Verify deny-over-allow behavior where applicable.
- [ ] Verify audit logging for auth decisions.

## 8. Audit networking and security controls

- [ ] Verify any IP allowlist or CIDR filtering behavior.
- [ ] Verify TLS and certificate handling assumptions.
- [ ] Verify purge protection defaults and retention behavior.
- [ ] Verify secure handling of secrets and key material in logs.
- [ ] Verify rate limiting, throttling, or retry behavior where applicable.

## 9. Audit observability and operability

- [ ] Verify audit logs are emitted for create, update, delete, recover, and purge paths.
- [ ] Verify metrics endpoints or other telemetry hooks.
- [ ] Verify health endpoints.
- [ ] Verify backup and restore operator workflows.
- [ ] Verify CLI parity for any supported API operation.

## 10. Compare behavior with Azure

- [ ] Verify request shape matches Azure where RocketVault claims parity.
- [ ] Verify response shape matches Azure where RocketVault claims parity.
- [ ] Verify HTTP status codes match Azure where RocketVault claims parity.
- [ ] Verify default values match Azure where RocketVault claims parity.
- [ ] Verify limit values match Azure where RocketVault claims parity.
- [ ] Verify error messages and codes are consistent enough for client compatibility.
- [ ] Verify pagination and filtering behavior.
- [ ] Verify API version compatibility or document the limitation.

## 11. Collect code evidence

- [ ] Record the exact RocketVault file paths for each feature.
- [ ] Record schema or migration files for any persisted feature.
- [ ] Record service files for business logic.
- [ ] Record API handler files for HTTP behavior.
- [ ] Record CLI files for user-facing command support.
- [ ] Record test files for each feature.

## 12. Run verification

- [ ] Run focused unit tests for touched services.
- [ ] Run focused repository or schema tests.
- [ ] Run focused API or integration tests, if available.
- [ ] Run a broader test pass for the affected subsystem.
- [ ] Capture any failures and classify them as implementation gaps or test gaps.

## 13. Classify each feature

- [ ] Mark exact matches.
- [ ] Mark partial matches.
- [ ] Mark missing features.
- [ ] Mark intentional exclusions.
- [ ] Add a one-line justification for each classification.

## 14. Produce the report

- [ ] Calculate overall parity percentage.
- [ ] Calculate parity by category.
- [ ] Rank gaps by user impact.
- [ ] Rank gaps by security risk.
- [ ] List blockers to full parity.
- [ ] List recommended fixes in priority order.
- [ ] Call out any Azure features RocketVault should not copy.

## 15. Final review

- [ ] Recheck that every major Azure feature family has at least one row in the matrix.
- [ ] Recheck that every major RocketVault subsystem has been traced.
- [ ] Recheck that findings are backed by code or documentation evidence.
- [ ] Recheck that the final summary answers whether RocketVault has all necessary Azure Key Vault features.
