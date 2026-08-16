# Known Bugs and Deferred Refactors

This file tracks open bugs and intentionally deferred items with root-cause analysis
and fix recipes for each entry.

---

## Open Bugs

### B1 — secrets table missing columns

**Status**: Fixed in commit `b46000b` (2026-03-08)
**Severity**: Resolved
**File**: `internal/db/db.go`

**What was fixed**: The `createOptimizedSchema` function's `CREATE TABLE secrets`
statement now includes both `deleted_at TIMESTAMP NULL` and
`purge_protection BOOLEAN NOT NULL DEFAULT FALSE` (lines 377-378). Corresponding
`ALTER TABLE secrets ADD COLUMN deleted_at ...` and
`ALTER TABLE secrets ADD COLUMN purge_protection ...` statements were also added to
`migrateSchema()` (lines 694-695) so existing databases are patched on startup.

See `.claude/database-init-patterns.md` for the `migrateSchema` pattern.

---

### B2 — Service-account JWT revocation gap

**Status**: Fixed in commit `229d982`
**Severity**: Resolved
**File**: `internal/services/oauth2/oauth2_service.go`, `internal/services/auth/authentication_service.go`

**What was fixed**: `IssueToken` now uses `client.ID` (not `uuid.Nil`) as the JWT jti.
`ValidateSession` branches on `claims.Role == model.RoleServiceAccount` and calls
`oauth2ClientRepo.GetByID(ctx, sessionID)`. If the client is not found (deleted),
disabled, or expired, the request is rejected immediately.

**Remaining limitation (by design)**: `RotateSecret` does not invalidate live tokens —
tokens remain valid until their JWT TTL expires after a secret rotation. This is standard
OAuth2 behavior: rotating a secret prevents *new* token issuance but not existing tokens.
The default 15m JWT expiry bounds the exposure window.

---

### B4 — `serve` initialized its DB connection and ServiceContainer twice

**Status**: Fixed in commit `1495e4b`
**Severity**: Resolved — was a startup-cost/correctness issue, not data loss
**File**: `cmd/root.go`, `cmd/serve.go`, `bootstrap/bootstrap.go`, `app/app.go`

**Root cause**: `persistentPreRun` (`cmd/root.go`) runs before every CLI command and
unconditionally opens a DB connection (`db.NewRepository(...).InitializeDB()`) and
builds a full `container.ServiceContainer` — which eagerly loads the JWT signing key,
initializes the OIDC service (a real discovery HTTP call to the issuer), and
initializes the software/HSM key provider — *before* it checks whether the command
is in the `systemCmds` allowlist. `serve` is in that allowlist (no auth required),
but that check only skips authentication, not the DB/container construction that
already happened. `serve()` then calls `bootstrap.Boot`, which independently builds
its own DB connection and `ServiceContainer` from scratch — the one actually wired
into the running server. Net effect: two DB connections opened and migrated, two
JWT-signing-key keychain reads, two OIDC discovery calls, and two key-provider inits
on every `rocketvault serve` startup, with the first of each pair immediately
discarded. Also caused a cosmetic "Rotation scheduler started" double-log: one line
logged inside `schedulerService.Start` (`internal/services/secrets/scheduler_service.go`),
a second, redundant one logged by its caller in `app.StartServer` (`app/app.go`) on
the same successful call — not a second scheduler, verified no second `.Start()` call
exists anywhere.

**Fix**: `serveCmd` now sets its own `PersistentPreRunE` (`servePreRun` in
`cmd/serve.go`), following the same pattern `cmd/vaults/preview_migration.go`
already uses for the same reason (skip the root pre-run's DB/container setup).
`servePreRun` installs only the logger on the context — `bootstrap.Boot` remains
the single place that builds the real DB connection and `ServiceContainer`.
Verified via full-repo grep that nothing on `serve`'s execution path (bootstrap,
app, server, api packages) reads any other context key `persistentPreRun` used to
set; `persistentPostRun`'s `common.DBClassKey` lookup already no-ops gracefully
when absent (covered by `TestPersistentPostRun_NoDBInContext`). Also removed the
redundant success-path log line in `app.StartServer`, since `scheduler.Start`
already logs the same message with the same `interval` field internally.
Bonus: this also fixes a latent staleness bug — the discarded pre-run container was
built from config *before* bootstrap injects vault secrets into Viper, so it was
never even representative of the real runtime config.

**Regression test**: `TestServeCmd_OverridesRootPersistentPreRun` and
`TestServePreRun_SetsLoggerInContext` in `cmd/cmd_test.go` assert `serveCmd` keeps
its own `PersistentPreRunE` so a future refactor can't silently re-inherit the
root's DB-initializing pre-run.

---

### B3 — Pre-upgrade JWTs rejected after v4.0.0 session-revocation fix

**Status**: Expected operational behavior — documented in
`docs/release-notes/v4.0.0-azure-rbac.md` § "Breaking changes" item 5
**Severity**: Low — self-resolving within one JWT lifetime (default 15m)
**File**: `internal/services/auth/authentication_service.go`,
`internal/services/oauth2/oauth2_service.go`

**Root cause**: Two distinct mechanisms, both introduced the same day across
commits `b68e787`, `67d52e2`, and `229d982` — not a single unified fix:

- **User sessions** (`b68e787`): prior to the fix, JWTs had a random UUID as the
  jti with no link to `user_sessions`. After the upgrade, `ValidateSession`
  parses jti as a session ID and calls `sessionRepo.IsSessionRevoked`, which
  internally catches `sql.ErrNoRows` for a missing row and returns
  `(revoked=true, err=nil)` — `ValidateSession` then rejects with
  `"session revoked"` → 401.
- **Service accounts** (`229d982`, superseding an intermediate `uuid.Nil`
  scheme from `67d52e2`): `ValidateSession` never calls `IsSessionRevoked` for
  `RoleServiceAccount` claims — it takes a separate branch that resolves jti as
  a client ID via `oauth2ClientRepo.GetByID`. A pre-upgrade token's random jti
  matches no `oauth2_clients` row, `GetByID` hits `sql.ErrNoRows` directly, and
  `ValidateSession` rejects with `"service account not found or revoked"` → 401.

**Impact**: All users logged in at the time of a v4.0.0 deploy will receive a 401
on their next request. They must re-authenticate. Service-account tokens issued
before the upgrade are similarly invalidated, via the separate client-lookup
path above — no credential rotation needed, just a fresh token.

**Mitigation**: Deploy during low-traffic hours. The 401 is safe and self-resolving.
No data is lost. Users and service accounts simply need to re-authenticate.

---

### B5 — CircuitBreaker Open→HalfOpen admission race and half-open wedge

**Status**: Fixed in commits `40b865b` (admission race) and `455461b` (half-open
wedge follow-up; `29f3c41` adds the deterministic repro test for the latter)
**Severity**: Resolved
**File**: `internal/retry/retry.go`

**What was fixed**: `Execute` previously read `state` under `RLock`, released
the lock, then acted on it unlocked — including an entirely unlocked read of
`lastFailure` — so concurrent callers could all observe a stale `Open` state,
each independently transition to `HalfOpen`, and each be admitted into the
half-open trial with no cap; `HalfOpenRequests` was only ever checked after a
successful call, never as an admission gate before `fn()` ran. `admit()` now
performs the state check, `Open`→`HalfOpen` transition, and half-open slot
reservation as one locked critical section, capping concurrent/total
half-open admission at `HalfOpenRequests` (`40b865b`).

A follow-up review caught a second, related defect this introduced:
`finishHalfOpen`'s failure branch delegated to `recordFailure`, which only
flips state back to `Open` once `cb.failures` reaches `FailureThreshold`. With
half-open admission now capped at `HalfOpenRequests` (well below
`FailureThreshold` in every shipped config), a half-open trial could fail
without ever reopening the breaker — permanently wedging it in `HalfOpen`
with no path back to `Open` or forward to `Closed`. `finishHalfOpen` now
reopens the breaker unconditionally on any half-open trial failure, matching
standard circuit-breaker semantics; `recordFailure` itself is untouched —
`executeClosed`'s failure path still uses it as before (`455461b`).
`40b865b` adds `TestCircuitBreaker_HalfOpenAdmissionIsCapped` to pin down the
admission-race fix, and `455461b` adds
`TestCircuitBreaker_HalfOpenFailureReopensImmediately` to exercise the
half-open reopen path under a production-shaped config. Neither test alone
actually reaches the specific state the wedge fix protects against —
`recordFailure()` only sets `state=Open` once `cb.failures` is already at or
above `FailureThreshold`, which happens to already hold by the time a
sequential trip reaches `Open`, so both tests still pass even against a
version of `finishHalfOpen` that delegates to `recordFailure`. `29f3c41`
closes that gap with a third test,
`TestCircuitBreaker_LateSuccessDoesNotCausePermanentHalfOpenWedge`, which
reproduces the real reachable path deterministically: a closed-state call
admitted before the trip completes successfully after the trip and calls
the unexported `recordSuccess()` directly (reachable since the test is in
package `retry`), zeroing `cb.failures` while `state` is already `Open` with
no check on `cb.state` — from there, `HalfOpenRequests` failed half-open
trials are never enough to re-cross `FailureThreshold` under the old
delegating-to-`recordFailure` logic. This test was verified to fail against
the pre-`455461b` `finishHalfOpen` and pass against the current fix.

---

### B6 — `SetRetryDefaults` retryable_errors defaults drifted from policy source of truth

**Status**: Fixed in commit `d13db0c`
**Severity**: Resolved
**File**: `internal/retry/config_loader.go`

**What was fixed**: `SetRetryDefaults` hand-duplicated the `database` and
`external_services` `retryable_errors` lists as inline string slices instead
of referencing `DatabasePolicy()`/`ExternalServicePolicy()`, the actual source
of truth. The `external_services` list had fallen out of sync — missing the
5xx-reason-phrase entries already present in `ExternalServicePolicy()` — which
silently disabled 5xx retry for any deployment that didn't explicitly
override `retry.external_services.retryable_errors` in its own config.
`SetRetryDefaults` now sets both defaults directly from
`DatabasePolicy().RetryableErrors`/`ExternalServicePolicy().RetryableErrors`,
so the two can no longer drift apart. `TestSetRetryDefaults` was extended to
assert both defaults equal their source `Policy` function's list exactly.

---

### B7 — OIDC login retried the non-idempotent OAuth2 authorization-code exchange

**Status**: Fixed in commit `10fce4e`
**Severity**: Resolved
**File**: `internal/services/auth/oidc_service.go`

**What was fixed**: `HandleCallback`'s call to `s.oauth2Config.Exchange`
redeems a single-use authorization code, but it was wrapped in the same
`withRetry`/`ExternalServicePolicy` retry policy used for idempotent calls
(`Verify`, `UserInfo`). If the exchange actually succeeded at the IdP but the
response was lost (e.g. a timeout), the retry replayed the already-consumed
code, which the IdP correctly rejects as `invalid_grant` — turning a
successful login into a failed one. `Exchange` now runs exactly once,
unwrapped; a failure surfaces immediately and the user restarts the login
flow to obtain a fresh code. `TestHandleCallback_ExchangeIsNeverRetried`
pins this down, accounting for `golang.org/x/oauth2`'s own internal
auth-style-probing retry (which is independent of, and not to be confused
with, this codebase's retry wrapper).

---

### B8 — OIDC callback's Verify/UserInfo retries could exceed a typical reverse-proxy timeout

**Status**: Fixed in commits `6f5e768` (new `interactive` retry tier, plumbing
only) and `257ff16` (wires `HandleCallback`'s `Verify`/`UserInfo` calls to it)
**Severity**: Resolved
**File**: `internal/retry/config.go`, `internal/retry/retry.go`,
`internal/services/retry/retry_service.go`, `internal/services/auth/oidc_service.go`

**What was fixed**: `HandleCallback`'s `Verify` and `UserInfo` calls were
retried under `ExternalServicePolicy`, whose worst-case backoff (5 attempts,
1s–30s) can sum to roughly 19.5s per call. Stacked across `HandleCallback`'s
synchronous, user-facing request path, this risked exceeding a typical 30s
reverse-proxy/browser timeout well before the retry budget was exhausted,
turning a slow-but-eventually-successful IdP call into a hard failure for the
end user. `6f5e768` adds a fourth retry tier, `retry.InteractivePolicy()`
(`Config.Interactive`, `RetryService.ExecuteInteractiveOperation`/
`GetInteractivePolicy`), with deliberately short defaults (2 attempts,
250ms–2s backoff) for synchronous request paths that can't risk exceeding a
proxy/browser timeout — plumbing only, not itself consumed by any caller.
`257ff16` routes `HandleCallback`'s `Verify` and `UserInfo` calls through the
new tier via a widened local `RetryExecutor` interface and a new
`withInteractiveRetry` helper; `Discovery` (a startup-time, not per-request,
call) is unchanged. `TestHandleCallback_VerifyAndUserInfoUseInteractivePolicy`
asserts both calls go through the interactive tier and not
`ExecuteExternalServiceOperation`.

---

### B13 — CLI `audit logs`/`audit report`/`audit config` bypassed the admin-only restriction enforced by their HTTP equivalents

**Status**: Fixed in commits `46e3686` (helper), `eaaaedf` (logs), `0013f91`
(report), `466d76c` (config)
**Severity**: High — confirmed by a live pentest run 2026-08-16
**File**: `cmd/audit/authz.go`, `cmd/audit/logs.go`, `cmd/audit/report.go`,
`cmd/audit/config.go`

**Root cause**: `api/audit.go`'s five HTTP handlers (`getAuditLogs`,
`getSOC2Report`, `getGDPRReport`, `getAuditConfig`, `patchAuditConfig`) each
correctly gate on `claims.Role != model.RoleAdmin` before touching
`ComplianceReportService`. CLI commands bypass the HTTP middleware chain
entirely and are individually responsible for reproducing the equivalent
check (`CLAUDE.md` § "CLI Authorization") — the three CLI equivalents under
`cmd/audit/` never did. Each `RunE` only checked that a service container was
present in context, then called straight into `sc.GetComplianceReportService()`.
A plain `role=user` account with no admin or audit grant could run `rocketvault
audit logs` or `rocketvault audit report --type soc2 ...` and get the full
cross-vault audit trail and a complete SOC2 report covering every user
including the admin — confirmed live before the fix.

**What was fixed**: Added `requireAuditAdmin(cmd *cobra.Command)
(*model.Claims, error)` (`cmd/audit/authz.go`), modeled directly on
`cmd/backup.go`'s pre-existing `requireBackupAdmin` — same category of check
(global admin gate, no vault to scope to). Called from the top of
`logsCmd.RunE`, `reportCmd.RunE`, and `configCmd.RunE`, immediately after
each command's existing service-container guard and before any flag parsing
or service call. `TestLogsCmd_NonAdmin_Forbidden`,
`TestReportCmd_NonAdmin_Forbidden`, and `TestConfigCmd_NonAdmin_Forbidden`
(`cmd/audit/audit_cmds_test.go`) each assert both the `forbidden` error and,
via `AssertNotCalled`, that the underlying `ComplianceReportService` method
was never invoked.

**Spec/plan**: `docs/superpowers/specs/2026-08-16-cli-audit-authz-fix-design.md`,
`docs/superpowers/plans/2026-08-16-cli-audit-authz-fix.md`.

---

## Deferred Refactors

Both items formerly tracked here (H3, M2) were re-investigated on 2026-08-14 and
found to be much smaller in scope than originally estimated — see git history for
each item's exact commit. Neither was actually large enough to warrant deferral;
both are now fixed. Kept below for history.

### H3 — Unexported global `globalDB *sql.DB` in `internal/db/db.go` — FIXED

**Tracked since**: 2026-04-30
**Status**: Fixed in commit `484a4ff`
**Severity**: Low (architectural) — not a runtime bug; no data loss risk

**Original claim vs. reality**: The original entry described an *exported*
`var DB *sql.DB` needing "20+ call sites across the codebase" threaded through
DI. Re-investigation found the actual variable, `globalDB`, was already
unexported and had exactly 3 readers, all inside `internal/db/db.go` itself
(`GetPerformanceMetrics`, `GetConnectionPoolStats`, `HealthCheck`) — every
external consumer already went through `DBRepository.GetDB()`/`d.db` via proper
DI. The "20+" figure didn't correspond to anything in the codebase.

**Fix applied**:
1. `GetConnectionPoolStats` and `HealthCheck` became methods on `*DBRepository`,
   reading `d.db` instead of the global.
2. `GetPerformanceMetrics` took a `conn *sql.DB` parameter instead of reading the
   global, so its (previously unused-in-most-callers) `ConnectionStats` field is
   now supplied explicitly by each caller — `hc.db` in `internal/health/health.go`,
   and `database.GetDB()` in `bootstrap/bootstrap.go`'s `dbPerformanceSnapshot`
   (which now returns a closure over the repository instead of being a bare
   package function, since it feeds the `rocketvault_db_*` Prometheus gauges via
   `metrics.MetricsScheduler` and genuinely needs live connection-pool stats).
3. `globalDB` and its assignment in `InitializeDB()` were deleted.
4. All ~30 test references to `globalDB` (across `db_test.go`, `db_edge_test.go`,
   `db_more_test.go`, `tags_test.go`) were updated to use the already-initialized
   repository instance in scope instead.

---

### M2 — `Context.Claims` was `jwt.MapClaims` instead of a typed struct — FIXED

**Tracked since**: 2026-04-30
**Status**: Fixed in commit `9898477`
**Severity**: Low (code quality) — no runtime bug found; see below

**Original claim vs. reality**: The original entry said this "produces obscure
panics when the JWT is malformed or a field is missing." Re-investigation found
no reachable path that panics: `Claims` is populated with all three keys, always,
inside `ApiSessionRequired`; `ApiHandler` (public routes) never touches it; and
invalid JWTs 401 before `Context` is even built. The fix recipe's proposed
`internal/domain/user.go`/`JWTClaims` also didn't match the codebase — no
`internal/domain` package exists, and `model.Claims` (the actual typed
upstream struct) has `UserID uuid.UUID`, not a string, so reusing it directly
would have required a wider type change than the untyped map warranted.

**Fix applied**: Added a purpose-built value type in `api/context.go`:
```go
type RequestClaims struct {
    UserID   string
    Username string
    Role     string
}
```
Value type (not a pointer), so a zero-value `Context` — as `ApiHandler` leaves it
for public routes — still yields safe empty-string reads instead of a
nil-pointer panic. `Context.Claims` changed from `jwt.MapClaims` to
`RequestClaims`; `ApiSessionRequired` now assigns the struct literal directly.
All ~37 call sites across 11 `api/*.go` files were converted from
`c.Claims["user_id"].(string)`/`c.Claims["role"].(string)` type assertions
(with their `ok`/`_` boilerplate) to plain `c.Claims.UserID`/`c.Claims.Role`
field access, and ~20 test files that built `Context{Claims: jwt.MapClaims{...}}`
were converted to `RequestClaims{...}` (including two test-only helper functions,
`newUserCtx`/`newCertCtx`, whose parameter types changed accordingly).

One genuine, intentional behavior change fell out of this: the old map-based
`ok` check let a handful of sites distinguish "claim key absent" (500 internal
error) from "claim present but invalid" (400 bad param) — a distinction that
was already unreachable in production per the investigation above. With a
plain string field there's no "absent" state to distinguish, so
`getUserID` (`api/backup_item.go`), `listUserSessions`, and `revokeAllSessions`
(`api/users.go`) now return 400 uniformly via `uuid.Parse` for both cases. Three
tests were updated to match (`TestGetUserID_MissingClaim_SetsErr`,
`TestListUserSessions_MissingUserIDInClaims_Returns400`,
`TestRevokeAllSessions_MissingUserID_Returns400`).

---

### F1 — api/context.go bypasses the service layer with three repository accessors

**Status**: Resolved (Plan A Tasks 1-6, committed 2026-08-14/2026-08-15)
**Severity**: Low (architectural) — no runtime bug; DDD pattern violation

**What was fixed**: `api/context.go` originally exposed three raw repository accessor methods:
- `sessionRepo()` → routed through `AuthenticationService.ListActiveSessions` (Task 1-2)
- `certPolicyRepo()` → routed through `CertificateService` policy methods (Task 3-4)
- `keyRotationPolicyRepo()` → routed through `KeyService` policy methods (Task 5-6)

The three accessors this plan targeted (`sessionRepo()`, `certPolicyRepo()`, `keyRotationPolicyRepo()`) are gone from `api/context.go`. `api/`'s remaining `internal/repositories` imports are filter value types passed to service methods (`api/audit.go`, `api/keys.go`, `api/certificates.go`), not repository access. Two direct container-repository reads remain outside this plan's scope: `api/keys.go:620` and `api/role_assignments.go:32` — not regressions, just not targeted by this plan.

**Plan reference**: `.claude/context-followup-cleanup-plan.md`, Plan A Tasks 1-6.

---

### I1 — `retry.service_operations` is intentionally unwired

**Status**: Not a bug — intentional design decision (investigated 2026-08-14)
**Severity**: N/A — architectural intention, not an issue
**Files**: `internal/services/retry/retry_service.go`, `config.go`, `CLAUDE.md`

**Root cause of confusion**: Earlier documentation incorrectly labeled
`retry.service_operations` as a "dead stub... not yet read by code." This was
inaccurate — `retry.service_operations` is fully parsed, has complete test
coverage, and provides a real API surface (`RetryService.ExecuteServiceOperation`
and `GetServiceOperationsPolicy`). It simply has no production callers at this time.

**Investigation findings**:
1. **HSM/PKCS#11 key operations**: Investigated as a candidate for service-operation
   retry (connection timeouts, transient remote-call failures). Ruled out: this
   codebase only supports SoftHSM2, a local shared library, so connection-refused
   and timeout failure modes don't realistically apply to the cryptographic tier.
2. **Background schedulers**: Investigated certificate renewal, soft-delete purge,
   and secret rotation as candidates. Ruled out: all are pure local DB/SQL work with
   zero network calls, so they fit `database` retry instead.

**Decision**: Keep `retry.service_operations` as intentional forward-looking
scaffolding for a hypothetical future feature (e.g., a cloud HSM backend, ACME-based
certificate issuer, or remote KMS) that would genuinely need a distinct retry tier
with different failure modes. The API exists, is tested, and is ready to be wired if
such a feature lands. No technical debt or risk — harmless and deliberate.

**Notes**:
- `ExecuteServiceOperation` and `GetServiceOperationsPolicy` in `retry_service.go`
  have accurate doc comments (no changes needed).
- `CLAUDE.md`'s "Configuration" section incorrectly listed this as a dead stub;
  corrected 2026-08-15 to remove `retry.service_operations` from the dead-stub list
  and added a clarifying note about intentional unwiring.
