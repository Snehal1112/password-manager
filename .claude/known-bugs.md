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

### B9 — JWT forgery via the HS256 "migration window" fallback

**Status**: Fixed 2026-08-16 — see
`docs/superpowers/plans/2026-08-16-remove-hs256-jwt-fallback.md`
**Severity**: Resolved — was High (full administrative takeover, confirmed by
live exploitation in `.claude/pentest-report-2026-08-16.md` § H1)
**File**: `internal/services/auth/jwt_service.go`,
`internal/container/service_container.go`

**Root cause**: `jwtService.ValidateToken` fell back to HMAC-SHA256
verification for any token whose header carried no `kid`, via
`validateHS256Fallback`. Three things made that fatal rather than merely
legacy:

1. The HMAC key was `JWTConfig.SecretKey`, read from `viper.GetString("jwt_secret")`
   — a static value committed to `.rocketvault.yaml` and present throughout git
   history. With HS256 the verification key *is* the signing key, so a public
   verification key means anyone can mint tokens.
2. `NewJWTServiceWithProvider` computed `migrationDeadline = time.Now().Add(config.MigrationWindow)`
   **at service construction**, so `jwt.migration_window: "24h"` restarted on
   every process boot. The window never closed.
3. `ValidateSession` only checks that the token's `jti` maps to a non-revoked
   session, and trusts the `role` claim inside the token — so an attacker could
   log in normally as a low-privilege user, reuse that real session id, and set
   `role: admin` in a forged token.

**Evidence**: a forged token (no `kid`, `role: admin`, real `jti` from a
`role=user` login, correct issuer/audience, signed with the committed
`jwt_secret`) was accepted by `GET /api/v1/users/` → HTTP 200 with the
admin-only user list. A random `jti` → 401 and a wrong secret → 401, confirming
the only missing control was the secrecy of the HMAC key.

**What was fixed**: the HS256 verification path is gone, not repaired. A token
without a `kid` header is rejected outright (`invalid JWT token: missing kid
header`); `legacyJWTService`/`NewJWTService` — the only code able to *mint* an
HS256 token — were deleted along with `JWTConfig.SecretKey` and
`JWTConfig.MigrationWindow`; and the container now treats a
`signing.NewProvider` failure as a fatal startup error instead of degrading to
symmetric signing. Repair was rejected because this branch has never shipped a
tagged release, so there was no population of legacy HS256 tokens to migrate —
the path protected zero real migrations while providing one complete
authentication bypass.
`TestJWTService_Provider_KidlessHS256Token_Rejected` pins the fix by replaying
the exploit with the leaked secret.

**Remaining, tracked separately**:
- Rotating `jwt_secret` and removing it from tracked config and git history is
  pentest finding **H4**.
- `ValidateSession` still trusts the JWT's `role` claim rather than re-reading
  the role from the database. With HS256 gone this requires compromise of the
  asymmetric private key to exploit, so it is defence-in-depth rather than a
  live hole; fixing it means a DB read per authenticated request and a decision
  about role-change propagation latency.

---

### B10 — Live secrets committed to git, recurrence of a fixed incident

**Status**: Fixed 2026-08-16 (structural fix; all four secrets rotated,
including `master_key` — see item 6 below, executed 2026-08-16 against the
real dev database with a full change log at
`.claude/master-key-rotation-log-2026-08-16.md`) — see
`docs/superpowers/plans/2026-08-16-secrets-in-git-remediation.md`. Git-history
purge ran 2026-08-17 (see item 9 below) — the "remaining, tracked separately"
gap this note used to describe is closed. One recurrence happened in between
(also item 9): a separate session re-tracked `.rocketvault.yaml` directly on
`v-4.0.0` and pushed it before the structural fix had merged there.
**Severity**: Resolved — was High (full offline decryption of every stored
secret, admin-token forgery via the paired H1 finding, and first-admin-bootstrap
takeover, confirmed by live git-history inspection in
`.claude/pentest-report-2026-08-16.md` § H4)
**File**: `.gitignore`, `.rocketvault.yaml`, `.rocketvault.yaml.example`,
`.github/workflows/go.yml`, plus 9 tracked docs/scripts/tests that duplicated
the same values

**Root cause**: `.claude/security-incident-2026-03-07.md` (2026-03-07) already
fixed this exact class of leak once — `git rm --cached` on the then-named
`.password-manager*.yaml` files, plus a `.gitignore` entry for that name
pattern. The very next commit touching this area, one day later, renamed the
project to RocketVault and introduced a brand-new `.rocketvault.yaml` — under a
name the old `.gitignore` pattern didn't cover. It has been tracked and
unrotated ever since. A second, unrelated `.gitignore` line
(`rocketvault-*`, under "Application binaries") looks like it might have been
meant to catch this too; it never could, because it requires no leading dot and
a trailing dash, and `.rocketvault.yaml` has neither. Nothing ever tested that
either pattern actually matched the file it needed to match — that is the
literal, specific root cause, verified with `git check-ignore -v
.rocketvault.yaml` (no output, exit 1, before this fix).

The same four secret values (`master_key`, `jwt_secret`, `bootstrap_token`,
`hsm.pin`) were also duplicated, in whole or in part, across 9 other tracked
files (docs, a test fixture, a capture script) — including one,
`scripts/README.md`, still quoting an even older, already-`git rm`'d secret
generation from `.password-manager-test.yaml` (removed from the working tree in
commit `cb93bc9`, but never purged from history, and apparently copy-pasted
into a doc before that removal).

**What was fixed**:
1. `.gitignore` — new block matching `.rocketvault.yaml`, `.rocketvault-*.yaml`,
   and `.rocketvault.yaml.local`, with a negation for the new
   `.rocketvault.yaml.example` template. Verified with `git check-ignore -v`
   against all four names.
2. `.rocketvault.yaml.example` — committed template with instructional
   placeholders, mirroring the existing `.env`/`.env.example` pattern. The real
   `.rocketvault.yaml` is `git rm --cached`'d (working tree untouched).
3. Two new CI steps in `.github/workflows/go.yml`'s `security` job: a
   structural check that no `.rocketvault*.yaml` variant is ever tracked again,
   and a denylist check for the exact secret bytes already known to be
   compromised. A gitleaks-based alternative was evaluated and rejected after
   producing 50 findings locally, nearly all false positives on test fixtures —
   see the design doc.
4. `bootstrap_token` rotated to a freshly generated value; the old one
   (`***SECRET-REMOVED-2026-08-17***`) is permanently compromised,
   never to be reused.
5. `jwt_secret`/`jwt.migration_window` deleted from `.rocketvault.yaml` outright
   rather than rotated — H1 (`docs/superpowers/plans/2026-08-16-remove-hs256-jwt-fallback.md`)
   made both keys fully unread by any Go code, so rotating a value nothing
   reads would be motion without effect.
6. `master_key` — **rotated**, 2026-08-16, with explicit human sign-off. Used
   H3's `rocketvault master-key rotate` tool
   (`docs/superpowers/plans/2026-08-16-master-key-rotation.md`, see § B12)
   against the real dev database: backed up `dev-rocketvault.db` first, dry-run
   verified (3 rows: 2 `secrets`, 1 `keys`; 1 HSM-backed key correctly skipped),
   real run matched the dry run exactly with no errors, `.rocketvault.yaml`
   updated to the new key, server restarted on the existing (pre-this-branch)
   binary to confirm rotation doesn't require the new code to be deployed.
   Verified at the database level (ciphertext for both `secrets` rows
   genuinely changed vs. the pre-rotation backup); a live decrypt-via-API
   round-trip was attempted but blocked by an unrelated, pre-existing CLI
   session/refresh-token issue — not chased further, and **still worth an
   operator double-check** (`docs/runbooks/master-key-rotation.md` step 7).
   Full step-by-step log: `.claude/master-key-rotation-log-2026-08-16.md`. The
   old placeholder key (`***SECRET-REMOVED-2026-08-17***`, base64
   for `0123456789abcdef0123456789abcdef`) is retired and treated as
   permanently compromised; the pre-rotation database backup
   (`dev-rocketvault.db.pre-rotation-2026-08-16`) remains sealed under it.
7. `hsm.pin` — documented as a manual `softhsm2-util --pin ... --new-pin ...`
   runbook (`docs/runbooks/hsm-pin-rotation.md`), not automated: it is real,
   shared PKCS#11 token state, not a config value.
8. Nine other tracked files with duplicated literal values fixed to placeholders
   or config-driven reads.
9. **Recurrence + git-history purge, 2026-08-17.** Before this branch's fix
   (item 1-2 above) had merged into `v-4.0.0`, a separate Claude Code session
   working directly on the main checkout ran its own master_key rotation and
   committed the result — including `.rocketvault.yaml`, still git-tracked on
   `v-4.0.0` at that point — in commit `79d3598` ("chore: rotate dev
   master_key, update compose healthcheck path"), which was pushed to
   `origin/v-4.0.0` before being noticed. This put a second `master_key` value
   live in public git history (repo confirmed public; confirmed not used in
   production) alongside the four original values. Response: (a) merged this
   branch's fix into `v-4.0.0` so the file stays untracked going forward; (b)
   ran a full `git-filter-repo` purge against a fresh mirror clone — removed
   every historical `.rocketvault*.yaml`/`.password-manager*.yaml` file
   entirely and scrubbed all 7 known secret literals (the original 6 plus the
   `79d3598` value) from every remaining blob, across all 1027 commits, 6
   branches, 7 tags; verified clean via a full object-level sweep (9401
   objects, zero matches) before force-pushing the rewritten history (no other
   clones/forks existed, confirmed by the human operator, so no collaborator
   coordination was needed); (c) rotated `master_key` a third time so the live
   value was never exposed anywhere in history. Full detail:
   `.claude/master-key-rotation-log-2026-08-16.md` (§ "Third rotation —
   2026-08-17"). **Residual risk**: any clone/fork/cache made before
   2026-08-17, outside the operator's knowledge, still has the pre-purge
   history — accepted, same as the four original values' pre-rotation
   exposure.

**Regression tests**: none in the traditional sense (no Go logic changed beyond
one test-fixture swap) — the "tests" for this fix are the CI gate itself
(Task 6) and the verification gate in the design doc, both grep-based against
the real repository content, run and confirmed clean before this entry was
written.

**Remaining, tracked separately**:
- `master_key` rotation: **executed** 2026-08-16 against the live database,
  see item 6 above and `.claude/master-key-rotation-log-2026-08-16.md` for the
  full step-by-step record. A live decrypt-via-API verification is still
  recommended as a final operator sanity check.
- the git history itself still contains every value listed above, recoverable
  by anyone who has ever cloned this repository —
  `docs/superpowers/plans/2026-08-16-git-history-secret-purge-followup.md` is the
  deferred `git filter-repo` + coordinated force-push procedure to actually purge
  it. Until that runs, treat every value named in this entry as permanently
  public, rotation notwithstanding.

---

### B11 — Cross-vault authorization bypass on flat data-plane routes

**Status**: Fixed in commit `b4fc132`
**Severity**: High — broken access control; per-vault revocation was not enforced
**Files**: `api/context.go`, `api/keys.go`

**Root cause**: `scopeFromRequest` (`api/context.go`) branched on route shape: a
vault scope for `/api/v1/vaults/{vault_name}/...`, an owner scope for the legacy
flat routes (`/api/v1/secrets/{id}`, `/keys/{id}`, `/certificates/{id}` and their
sub-routes). An owner scope's repository predicate is `user_id = ?` with no
`vault_id` term at all (`internal/repositories/scope_predicate.go`), and
`model/scope.go` had already flagged `ScopeOwner` as "P1 only; retired in P2".
Meanwhile `PolicyMiddleware` authorized every flat-route request against the
**default** vault, because `VaultResolutionMiddleware` resolves
`model.DefaultVaultName` for any route with no `vault_name` variable. So the
authorization decision and the data lookup disagreed about which vault the
request targeted: a caller holding any data-plane grant on the default vault
could keep reading — and, with a set/create grant, writing — resources they had
created in **any other vault**, including one where their role assignment had
been explicitly revoked. Confirmed by live exploitation during the 2026-08-16
pentest (`.claude/pentest-report-2026-08-16.md` § H2): after
`DELETE .../role-assignments/{id}` returned 200, the vault-scoped route returned
403 for the secret while `GET /api/v1/secrets/{id}` still returned its value.

Secrets and certificates were affected on every flat read and write. Keys were
affected on get/list/update/versions only: `KeyService.DeleteKey`,
`KeyService.RotateKey` and `cryptoService.loadAndAuthorize` each carry an in-Go
"B6 conjunction" that re-applies the vault term when the scope is owner-scoped.
`deleteSecret` and `deleteCertificate` were already immune — both build
`model.NewVaultScope` by hand instead of calling the helper — which is why the
bug survived: the pattern was known and applied to two handlers out of 35 call
sites.

**Fix**: `scopeFromRequest` now returns `model.NewVaultScope(vaultID, userID)`
for every route shape. The vault id needed no change — `vaultIDFromRequest`
already resolved the default vault for flat routes, which is the same vault
`PolicyMiddleware` checks. `createKey`'s response read-back (`api/keys.go`), the
only other owner-scope construction on the request path, changed with it, so
`grep -rn "NewOwnerScope" api/` is now empty. `deleteSecret`/`deleteCertificate`
keep their hand-built scopes as belt-and-braces; only their comments changed.
Regression coverage is in `api/flat_route_vault_scope_test.go`: real SQLite
repositories behind the real router, seeding a caller-owned resource in another
vault and asserting 404 on the flat route, each paired with a positive control
in the resolved vault.

**Known behavior change**: flat-route listing (`GET /secrets`, `/keys`,
`/certificates`, `POST /secrets/export`, the deleted-item lists) now returns
every row in the default vault rather than only the caller's own rows across
every vault — the Azure-parity "vault members see all" semantic already in force
on the vault-scoped routes. See
`docs/release-notes/v4.1.0-role-parity-and-authz-fix.md`.

**Deliberately not fixed here** (bounded fix, see
`docs/superpowers/specs/2026-08-16-flat-route-vault-scope-fix-design.md`
§ "Not in scope"): `ScopeOwner` still exists in `model/scope.go` and the
repository predicate; `cmd/version.go` still builds
`model.NewOwnerScope(uuid.Nil, userID)` on the CLI path, which needs its own
`vaultcli.ResolveVaultID` + `RequireDataAction` treatment; and the three B6
conjunctions in the key services are now unreachable from HTTP but were left in
place, along with their comments claiming flat routes still reach them.

---

### B12 — All secrets and software key PEMs sealed with a predictable, git-committed master key

**Status**: Fixed on branch `v-4.0.0` (2026-08-16) — tool and startup guard landed; the
rotation itself against the real dev/prod databases is tracked separately as H4
**Severity**: High — confirmed by live exploitation during the 2026-08-16 penetration test
**File**: `common/encrypt.go`, `common/masterkey.go`, `bootstrap/bootstrap.go`,
`internal/rekey/`, `cmd/master_key.go`, `.rocketvault.yaml`

**Root cause**: Secret values, software (non-HSM) key PEMs, and certificate private keys are all
sealed with AES-256-GCM under a single key read from `viper.GetString("master_key")`. The AES-GCM
construction is correct (fresh random 12-byte nonce per seal, prepended, real AEAD). The defect was
the key *value*: the committed `.rocketvault.yaml` shipped
`master_key: "***SECRET-REMOVED-2026-08-17***"`, which base64-decodes to the ASCII
string `0123456789abcdef0123456789abcdef` — a placeholder, in git, identical in every deployment
that never changed it. Anyone holding a copy of the database (stolen backup, snapshot,
decommissioned disk, or the repository itself) decrypted every secret offline. Nothing in the
codebase checked key quality, and the two length checks even disagreed: `EncryptSecret` accepted
`len(key) >= 32` while `DecryptSecret` required `== 32`.

Rotating the key was not a one-line config change either: with no re-encryption path anywhere in
the codebase, changing `master_key` made every existing row permanently undecryptable. That is why
the fix is a migration tool, not just a guard.

**Blast radius** (every column sealed with this key, established by mapping all nine callers of
`common.EncryptSecret`/`DecryptSecret` to the columns they write): `secrets.value`,
`secret_versions.value`, `keys.value`, `key_versions.value`, `certificates.private_key`. The
`keys` entry includes `internal/signing.SelfPKIProvider`'s JWT signing key, which is stored as an
ordinary `keys` row. PKCS#11/HSM key rows (`pkcs11:` prefix) hold token handles, not ciphertext,
and are unaffected. User passwords and OAuth2 client secrets are bcrypt hashes; TOTP secrets are
stored in plaintext (a separate issue) — none of those are touched by rotation.

**Fix**:
1. `common.EncryptWithKey`/`DecryptWithKey`/`ParseMasterKey` — key-parameterized AES-256-GCM
   primitives, so one process can open under the old key and seal under the new one.
   `EncryptSecret`/`DecryptSecret` keep their signatures and now agree on requiring exactly 32
   bytes.
2. `common.ValidateMasterKey` — rejects a missing/malformed/wrong-length key, the known-compromised
   committed default (constant-time compare), all-printable-ASCII keys, and keys with fewer than 16
   distinct byte values.
3. `bootstrap.ConfigurationValidator.ValidateMasterKey`, called as `setup` Step 1c (after Step 1b
   injects vault-sourced secrets into Viper, since that injection can supply `master_key` itself) —
   the server now refuses to start on a weak key, with no override flag.
4. `internal/rekey` — plan-then-apply re-encryption over the five columns above using raw
   dialect-aware SQL (repositories are scope- and soft-delete-filtered and would re-encrypt on the
   way through, so they are the wrong layer). Each row is classified by trying the **new** key
   first, which makes an interrupted run safe to resume without double-encrypting; `pkcs11:` rows
   are skipped; updates run in batched transactions guarded by `AND <column> = <old ciphertext>`
   with `RowsAffected() == 1` asserted, so a still-running server causes a loud abort instead of
   silent data loss.
5. `rocketvault master-key rotate --new-key-env NEW_MASTER_KEY [--old-key-env ...] [--dry-run]` —
   admin-only CLI driving the engine. Keys are passed by environment-variable *name*, never in
   argv; the new key must pass `ValidateMasterKey`; neither key nor any plaintext is ever logged.

**Regression tests**: `common/masterkey_test.go` (weak-key rejection, including the exact committed
value), `common/encrypt_key_test.go` (key-parameterized round-trip, wrong-key failure),
`internal/rekey/classify_test.go` and `internal/rekey/rekey_test.go` (dry-run writes nothing,
full re-encryption round-trips under the new key, second run is a no-op, partial migration resumes,
`pkcs11:` rows untouched, wrong old key aborts with no writes), `bootstrap/bootstrap_test.go`
(startup guard), `cmd/master_key_test.go` (admin gate, key resolution).

**Operational note**: after this landed, the server refuses to boot against the repository's
working-tree `.rocketvault.yaml` (no longer git-tracked, but its value is still recoverable from
git history) until the key is rotated — intended. The procedure is
`docs/runbooks/master-key-rotation.md`. Backups taken before a rotation remain encrypted with the
old key and need the old key to restore.

**Related**: H4 (removing the committed key from `.rocketvault.yaml` and moving custody to the
environment/secret store) invokes this tool to perform the actual rotation. Envelope encryption
(per-secret data keys wrapped by a KEK, making future rotations O(1) instead of O(rows)) was
considered and deliberately deferred — it is a storage-format change touching every read path.

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
