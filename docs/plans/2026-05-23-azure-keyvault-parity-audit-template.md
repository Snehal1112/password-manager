# RocketVault Azure Key Vault Parity Audit Template

**Date:** 2026-05-23  
**Status:** Template  
**Purpose:** Use this document to assess whether RocketVault matches Azure Key Vault feature-by-feature, behavior-by-behavior.

## How to use

1. Start with the official Azure Key Vault documentation for the specific feature family.
2. Trace the matching RocketVault implementation in API, service, repository, schema, CLI, config, and tests.
3. Mark each row as `exact`, `partial`, `missing`, `out of scope`, or `unknown`.
4. Record evidence, not assumptions.
5. Finish with a gap summary ranked by user impact and security risk.

## Scope

Audit the following areas separately:

- Secrets
- Keys
- Certificates
- Access control and authentication
- Soft-delete and purge protection
- Networking and firewall behavior
- Observability and audit logging
- Backup and restore
- Limits, quotas, pagination, and error handling
- API version compatibility

Treat Azure Managed HSM as a separate appendix unless the audit explicitly includes it.

## Feature Matrix

| Category | Azure feature | Azure behavior / limit | Score | RocketVault status | Evidence in RocketVault | Test evidence | Notes / gaps |
|---|---|---|---|---|---|---|---|
| Secrets | Secret CRUD, list, versions, tags, expiry, metadata | Azure secret versioning, metadata, and lifecycle semantics | 1.0 | exact | [api/secrets.go](/home/numericlabs/data/rocket/rocketvault/api/secrets.go), [internal/services/secrets/secret_service.go](/home/numericlabs/data/rocket/rocketvault/internal/services/secrets/secret_service.go), [internal/repositories/secret_repository.go](/home/numericlabs/data/rocket/rocketvault/internal/repositories/secret_repository.go) | [internal/services/secrets/content_type_test.go](/home/numericlabs/data/rocket/rocketvault/internal/services/secrets/content_type_test.go), [internal/repositories/secret_repository_content_type_test.go](/home/numericlabs/data/rocket/rocketvault/internal/repositories/secret_repository_content_type_test.go) | Core secret operations appear implemented and aligned with the existing Azure-compatible naming and validation rules. |
| Secrets | Secret content types | Azure `contentType` metadata on secrets | 1.0 | exact | [internal/services/secrets/secret_service.go](/home/numericlabs/data/rocket/rocketvault/internal/services/secrets/secret_service.go), [internal/db/db.go](/home/numericlabs/data/rocket/rocketvault/internal/db/db.go), [internal/repositories/secret_repository.go](/home/numericlabs/data/rocket/rocketvault/internal/repositories/secret_repository.go) | [internal/services/secrets/content_type_test.go](/home/numericlabs/data/rocket/rocketvault/internal/services/secrets/content_type_test.go), [internal/repositories/secret_repository_content_type_test.go](/home/numericlabs/data/rocket/rocketvault/internal/repositories/secret_repository_content_type_test.go) | Implemented with an allowlist and persisted schema support. |
| Secrets | Soft-delete and purge protection | Azure soft-delete, recover, purge, retention, purge protection | 1.0 | exact | [internal/repositories/secret_repository.go](/home/numericlabs/data/rocket/rocketvault/internal/repositories/secret_repository.go), [internal/db/db.go](/home/numericlabs/data/rocket/rocketvault/internal/db/db.go) | [internal/cache/secret_cache_test.go](/home/numericlabs/data/rocket/rocketvault/internal/cache/secret_cache_test.go) | Secret delete/recover/purge behavior is present; verify Azure retention defaults during the audit. |
| Keys | Key CRUD, list, versions, sign, verify, encrypt, decrypt, rotate | Azure key lifecycle and crypto operations | 1.0 | exact | [internal/repositories/key_repository.go](/home/numericlabs/data/rocket/rocketvault/internal/repositories/key_repository.go), [internal/services/keys/crypto_service.go](/home/numericlabs/data/rocket/rocketvault/internal/services/keys/crypto_service.go), [api/keys.go](/home/numericlabs/data/rocket/rocketvault/api/keys.go) | [internal/services/keys/wrap_key_test.go](/home/numericlabs/data/rocket/rocketvault/internal/services/keys/wrap_key_test.go) | Core key management and cryptographic operations are implemented in the service layer and exposed via the API. |
| Keys | Key wrap and unwrap | Azure `wrapKey` / `unwrapKey` | 1.0 | exact | [api/keys.go](/home/numericlabs/data/rocket/rocketvault/api/keys.go), [internal/services/keys/crypto_service.go](/home/numericlabs/data/rocket/rocketvault/internal/services/keys/crypto_service.go) | [internal/services/keys/wrap_key_test.go](/home/numericlabs/data/rocket/rocketvault/internal/services/keys/wrap_key_test.go) | RSA-OAEP wrapping is present and wired through API + service. |
| Keys | Soft-delete and purge protection | Azure deleted key recovery and purge semantics | 1.0 | exact | [internal/repositories/key_repository.go](/home/numericlabs/data/rocket/rocketvault/internal/repositories/key_repository.go), [internal/db/db.go](/home/numericlabs/data/rocket/rocketvault/internal/db/db.go) | [internal/repositories/key_repository.go](/home/numericlabs/data/rocket/rocketvault/internal/repositories/key_repository.go) | Key soft-delete, recovery, purge, and purge protection paths are present; compare final retention semantics to Azure. |
| Certificates | Certificate CRUD, list, import, versioning | Azure certificate lifecycle and metadata behavior | 1.0 | exact | [internal/repositories/certificate_repository.go](/home/numericlabs/data/rocket/rocketvault/internal/repositories/certificate_repository.go), [internal/services/certificates/certificate_service.go](/home/numericlabs/data/rocket/rocketvault/internal/services/certificates/certificate_service.go), [api/certificates.go](/home/numericlabs/data/rocket/rocketvault/api/certificates.go) | [internal/services/certificates/renewal_service_test.go](/home/numericlabs/data/rocket/rocketvault/internal/services/certificates/renewal_service_test.go) | Certificate lifecycle and retrieval are implemented. |
| Certificates | Certificate auto-renewal | Azure `lifetime_action`-style renewal behavior | 1.0 | exact | [internal/services/certificates/renewal_service.go](/home/numericlabs/data/rocket/rocketvault/internal/services/certificates/renewal_service.go), [internal/services/certificates/renewal_scheduler.go](/home/numericlabs/data/rocket/rocketvault/internal/services/certificates/renewal_scheduler.go), [bootstrap/bootstrap.go](/home/numericlabs/data/rocket/rocketvault/bootstrap/bootstrap.go) | [internal/services/certificates/renewal_service_test.go](/home/numericlabs/data/rocket/rocketvault/internal/services/certificates/renewal_service_test.go) | Scheduler-driven renewal is implemented and wired into bootstrap. |
| Certificates | Soft-delete and purge protection | Azure deleted certificate recovery and purge semantics | 1.0 | exact | [internal/repositories/certificate_repository.go](/home/numericlabs/data/rocket/rocketvault/internal/repositories/certificate_repository.go), [internal/db/db.go](/home/numericlabs/data/rocket/rocketvault/internal/db/db.go) | [internal/repositories/certificate_repository.go](/home/numericlabs/data/rocket/rocketvault/internal/repositories/certificate_repository.go) | Soft-delete, recovery, purge, and purge protection paths are present. |
| Access control | RBAC and per-operation permissions | Azure role-based access plus fine-grained operation control | 1.0 | exact | [internal/services/authorization/rbac_service.go](/home/numericlabs/data/rocket/rocketvault/internal/services/authorization/rbac_service.go), [internal/repositories/access_policy_repository.go](/home/numericlabs/data/rocket/rocketvault/internal/repositories/access_policy_repository.go) | [internal/services/authorization/rbac_integration_test.go](/home/numericlabs/data/rocket/rocketvault/internal/services/authorization/rbac_integration_test.go) | RBAC is implemented and access-policy storage exists; verify Azure parity for precedence and deny/allow semantics. |
| Access control | OAuth2 service accounts | Azure client credentials-style app authentication | 1.0 | exact | [internal/services/oauth2/oauth2_service.go](/home/numericlabs/data/rocket/rocketvault/internal/services/oauth2/oauth2_service.go), [api/oauth2.go](/home/numericlabs/data/rocket/rocketvault/api/oauth2.go) | [internal/services/oauth2/oauth2_service_test.go](/home/numericlabs/data/rocket/rocketvault/internal/services/oauth2/oauth2_service_test.go) | Service-account authentication is present and used by the vault client flow. |
| Networking | CORS / origin allowlist and request filtering | Azure firewall / allowlist analogs | 0.5 | partial | [internal/middleware/middleware.go](/home/numericlabs/data/rocket/rocketvault/internal/middleware/middleware.go) | [internal/middleware/middleware_test.go](/home/numericlabs/data/rocket/rocketvault/internal/middleware/middleware_test.go) | There is allowlist-based request filtering, but Azure Key Vault firewall behavior still needs direct comparison. |
| Observability | Health, metrics, audit logging | Azure monitoring and activity visibility | 0.5 | partial | [internal/health/health.go](/home/numericlabs/data/rocket/rocketvault/internal/health/health.go), [internal/logging/](/home/numericlabs/data/rocket/rocketvault/internal/logging/), [internal/repositories/key_repository.go](/home/numericlabs/data/rocket/rocketvault/internal/repositories/key_repository.go) | [internal/health/health.go](/home/numericlabs/data/rocket/rocketvault/internal/health/health.go) | Health and performance metrics are present; Prometheus-style parity still needs explicit verification. |
| Backup / restore | Backup and restore workflows | Azure backup/restore semantics for vault objects | 0.5 | partial | [internal/backup/](/home/numericlabs/data/rocket/rocketvault/internal/backup/), [cmd/backup.go](/home/numericlabs/data/rocket/rocketvault/cmd/backup.go) |  | Backup support exists, but restore semantics and feature-level Azure equivalence still need to be checked. |
| API compatibility | REST route coverage and response shape | Azure route parity, request/response compatibility, versioning | 0.5 | partial | [api/](/home/numericlabs/data/rocket/rocketvault/api/), [docs/api-developer-guide.md](/home/numericlabs/data/rocket/rocketvault/docs/api-developer-guide.md), [docs/api-specification.yaml](/home/numericlabs/data/rocket/rocketvault/docs/api-specification.yaml) |  | The API surface is broad, but parity should still be validated route-by-route against Azure docs. |

Use one row per Azure capability. If a capability has multiple behaviors, split it into multiple rows.

## Evidence Checklist

- Azure docs page or API reference URL recorded
- RocketVault file path recorded
- Request and response shape verified
- Status codes and error codes verified
- Persistence path verified, if applicable
- Schema or migration verified, if applicable
- CLI support verified, if applicable
- Unit or integration test verified
- Behavior compared against Azure semantics, not only presence of code

## Scoring Rules

| Score | Label | When to use |
|---|---|---|
| `1.0` | exact | Feature is implemented, code paths are confirmed, behavior aligns with Azure semantics, and there is passing test coverage. |
| `0.5` | partial | Feature code exists but one or more of the following is unconfirmed: Azure behavior alignment, passing tests, full lifecycle coverage, correct limits/defaults. |
| `0.0` | missing | Feature is absent from the codebase or its implementation is a stub with no functional effect. |
| — | out of scope | RocketVault intentionally does not implement this Azure capability (e.g. cloud-only HSM). Excluded from the denominator. |
| — | unknown | Not yet investigated. Treated as `0.0` in parity calculations until resolved. |

## Reviewer Score Assignment Guide

Use this decision flow every time you score a row. Follow each step in order and stop at the first matching answer.

**Step 1 — Does the feature exist at all?**
- No code path, no API route, no domain field → `0.0 / missing`
- Yes → continue to Step 2.

**Step 2 — Is it exercised by passing tests?**
- No tests and no integration coverage → `0.5 / partial` at best.
- Yes → continue to Step 3.

**Step 3 — Does the behavior match Azure on the happy path?**
Check all of:
- Request and response shape match Azure JSON fields
- HTTP status codes match Azure (e.g. 200 vs 201, 404 vs 409)
- Defaults and limits match Azure (e.g. secret size ≤ 25 KB, retention 7–90 days)
- All yes → continue to Step 4.
- Any no → `0.5 / partial` and note the specific divergence.

**Step 4 — Does the behavior match Azure on error paths?**
Check all of:
- Invalid input returns the expected 4xx code
- Missing or expired resource returns the expected status
- Deny-over-allow access control works the same way
- All yes → continue to Step 5.
- Any no → `0.5 / partial` and note the specific divergence.

**Step 5 — Does the feature participate in lifecycle flows?**
For features where Azure mandates lifecycle integration, check:
- Soft-delete filter applied to list and get queries where required
- Versioning increments correctly
- Purge protection blocks premature permanent deletion
- Rotation or renewal wired end-to-end
- All applicable → `1.0 / exact`.
- Any gap → `0.5 / partial`.

If you cannot verify a step with available code or documentation, mark the row `unknown` and add a note explaining what is missing.

## Parity Formula

### Unweighted parity

Use this when all categories are treated equally:

`parity % = (sum of in-scope row scores ÷ number of in-scope rows) × 100`

### Weighted parity

Use this when you want higher-importance categories to have more influence on the headline number.

`parity % = (sum of (score × category_weight) for all in-scope rows ÷ sum of category_weight for all in-scope rows) × 100`

### Suggested category weights

| Category | Suggested weight | Rationale |
|---|---|---|
| Access control | 2.0 | Incorrect access control is a direct security risk |
| Secrets | 1.5 | Core vault capability; directly affects data confidentiality |
| Keys | 1.5 | Core vault capability; directly affects cryptographic operations |
| Certificates | 1.5 | Core vault capability; directly affects PKI and TLS |
| Networking | 1.0 | Defense-in-depth; important but not a primary vault function |
| Observability | 1.0 | Required for auditability and incident response |
| Backup / restore | 1.0 | Required for recovery guarantees |
| API compatibility | 1.0 | Required for client portability |

Adjust weights to reflect your organisation's risk profile. Always record the weights used in the audit report summary so results can be reproduced.

## Required Questions Per Feature

For each Azure feature, answer the following:

- Does RocketVault expose the feature at all?
- Is the public API shape compatible?
- Does the feature behave the same on success?
- Does the feature fail the same way on invalid input?
- Are defaults and limits equivalent?
- Does the feature participate in delete, recover, purge, and version flows where Azure does?
- Is the feature documented and tested?
- Is the feature intentionally missing, and if so, why?

## Output Format

### Summary

| Field | Value |
|---|---|
| Audit date | |
| RocketVault commit / release | |
| Azure KV docs reference date | |
| Total in-scope rows | |
| Rows scored 1.0 (exact) | |
| Rows scored 0.5 (partial) | |
| Rows scored 0.0 (missing) | |
| Rows marked out of scope | |
| Rows marked unknown | |
| Unweighted parity % | |
| Weighted parity % | |
| Category weights used | |
| Formula | `(sum of scores ÷ in-scope rows) × 100` for unweighted; see Parity Formula section for weighted |

### Findings

| Severity | Category | Finding | Impact | Recommendation |
|---|---|---|---|---|
| High |  |  |  |  |
| Medium |  |  |  |  |
| Low |  |  |  |  |

### Next Steps

- Short-term fixes
- Medium-term gaps
- Deferred exclusions

## Reference Inputs

- [RocketVault parity design](/home/numericlabs/data/rocket/rocketvault/docs/plans/2026-03-08-azure-keyvault-parity-design.md)
- [RocketVault Azure KV feature spec](/home/numericlabs/data/rocket/rocketvault/docs/superpowers/specs/2026-04-30-azure-kv-features-design.md)
- Microsoft Azure Key Vault documentation
