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

### B14 — CLI `vaults get`/`vaults list` performed zero authorization checks

**Status**: Fixed in commit `93339d1`
**Severity**: High — any authenticated CLI user, including a plain `user` role
with no vault grants, could enumerate every vault's metadata instance-wide
**File**: `cmd/vaults/authz.go`, `cmd/vaults/get.go`, `cmd/vaults/list.go`

**Root cause**: Same bug class as B11/B13 — `cmd/vaults/get.go` and
`cmd/vaults/list.go` bypass the HTTP middleware chain entirely and never
reproduced the `CanManageVault` check their HTTP equivalents (`api/vault.go`'s
`getVault`/`listVaults`) both require.

**What was fixed**: Added `requireCanListVaults` (`cmd/vaults/authz.go`,
checked against `uuid.Nil` since list has no single target vault, mirroring
`listVaults`) and wired the pre-existing `requireCanManageVault` into
`get.go`. `TestVaultsGet_ForbiddenWithoutGrant`/
`TestVaultsList_ForbiddenWithoutGlobalGrant` (`cmd/vaults/vaults_more_test.go`)
pin the fix.

**Spec/plan**: `docs/plans/2026-08-18-azure-keyvault-parity-audit.md` (Critical
Finding #1/F2), `docs/superpowers/plans/2026-08-18-security-short-term-fixes.md`
(Task 1).

---

### B15 — `RestoreSecret`/`RestoreKey`/`RestoreCertificate` wrote the blob's embedded vault, not the caller's authorized vault

**Status**: Fixed in commit `c5bf97d`
**Severity**: High — a caller with restore permission in one vault could
silently write a restored secret/key/certificate into any vault the backup
blob happened to reference
**File**: `internal/backup/item_backup.go`, `api/backup_item.go`

**Root cause**: `ItemBackupService.RestoreSecret`/`RestoreKey`/
`RestoreCertificate` decoded the backup blob and persisted the item using the
`vault_id` embedded inside that blob, instead of the vault the HTTP request
was actually authorized against. The audit only named the `RestoreSecret`
instance, but `RestoreKey`/`RestoreCertificate` shared the identical bug.

**What was fixed**: All three methods gained a `vaultID` parameter — the
vault resolved from the authorized request (`vaultIDFromRequest`) — and now
write that value onto the restored item's `VaultID`, never the blob's.
`TestRestoreSecretWritesAuthorizedVaultNotBlobVault`
(`internal/backup/item_backup_test.go`) and the HTTP-level regression test in
`api/backup_item_test.go` pin the fix.

**Spec/plan**: `docs/plans/2026-08-18-azure-keyvault-parity-audit.md`
(Secrets findings, High), `docs/superpowers/plans/2026-08-18-security-short-term-fixes.md`
(Task 2).

---

### B16 — Role-assignment grant/revoke never audit-logged the success path

**Status**: Fixed in commit `62c4b7b`
**Severity**: High — the single most security-sensitive action in the RBAC
system (granting/revoking a per-vault Azure role) left no forensic trail;
`RevokeAssignment` had zero audit calls on any path
**File**: `internal/services/authorization/role_assignment_service.go`

**Root cause**: `RoleAssignmentService.AssignRole` only logged on failure
paths; `RevokeAssignment` didn't call `LogAuditInfo`/`LogAuditError` at all.
A malicious admin who self-granted excess privilege then revoked it was
invisible to `GET /audit/logs`.

**What was fixed**: Added `s.log.LogAuditInfo(...)` success-path calls to
both methods (`"assign_role"`/`"revoke_role_assignment"`, matching the
existing sentinel-error/`LogAuditInfo` convention).
`TestAssignRole_LogsSuccessAudit`/`TestRevokeAssignment_LogsSuccessAudit`
(`internal/services/authorization/role_assignment_service_test.go`) pin the
fix.

**Spec/plan**: `docs/plans/2026-08-18-azure-keyvault-parity-audit.md`
(Critical Finding #6), `docs/superpowers/plans/2026-08-18-security-short-term-fixes.md`
(Task 3).

---

### B17 — Recover/purge success was never audit-logged for secrets, keys, or certificates

**Status**: Fixed in commit `51d8bae`
**Severity**: High — an irreversible purge of vault material produced zero
audit record of who did it or when; vaults were the only domain that logged
this correctly
**File**: `internal/services/secrets/secret_service.go`,
`internal/services/keys/key_service.go`,
`internal/services/certificates/certificate_service.go`

**Root cause**: `RecoverSecret`/`PurgeSecret`/`RecoverKey`/`PurgeKey`/
`RecoverCertificate`/`PurgeCertificate` only logged the "not found" guard
failure, never a success-path audit row, unlike `vault_service.go`'s
`DeleteVault`/`RecoverVault`/`PurgeVault`.

**What was fixed**: Added `s.logger.LogAuditInfo(scope.ActorID().String(),
"<recover|purge>_<secret|key|certificate>", "success", ...)` to all six
methods' success paths, matching the existing `vault_service.go` pattern.
Six new tests (`*_LogsSuccessAudit`) across
`internal/services/secrets/secret_scope_service_test.go`,
`internal/services/keys/key_soft_delete_test.go`, and
`internal/services/certificates/cert_soft_delete_test.go` pin the fix.

**Spec/plan**: `docs/plans/2026-08-18-azure-keyvault-parity-audit.md`
(Critical Finding #7), `docs/superpowers/plans/2026-08-18-security-short-term-fixes.md`
(Task 4).

---

### B18 — SOC2 report's `AuthSuccesses`/`AuthFailures` counters were silently wrong in production

**Status**: Fixed in commit `4e50061`
**Severity**: High — a SOC 2 compliance report generated from real production
data showed a 100% authentication failure rate regardless of reality
**File**: `internal/services/auth/authentication_service.go`,
`internal/container/service_container.go`

**Root cause**: The real `AuthenticateUser`/`issueSession` write path only
called `s.logger.LogAuditInfo`/`LogAuditError` (a lossy legacy shim that
never populates `AuditLog.Outcome`), never `AuditService.RecordEvent` (the
rich path HTTP middleware already uses). Every real login, success or
failure, persisted `Outcome = ""`, which `ComplianceReportService`'s SOC2
report counts as neither a success nor a failure it can attribute correctly.
The existing unit test masked this by seeding `Outcome` directly into the
repo, bypassing the real write path entirely.

**What was fixed**: `AuthenticationConfig`/`authenticationService` gained an
optional `AuditService auditServices.AuditServiceInterface` field, wired in
`internal/container/service_container.go`. `AuthenticateUser`'s four failure
branches and `issueSession`'s success log now route through
`AuditService.RecordEvent` (falling back to the old `LogAuditInfo` path only
when `AuditService` is nil, e.g. in tests that don't set it up).
`TestAuthenticateUser_RecordsRichAuditOutcomeOnSuccessAndFailure`
(`internal/services/auth/authentication_service_test.go`) exercises the real
write path end-to-end and asserts a persisted `Outcome` of `"success"`/
`"failure"`, not the seeded-row shortcut the old test used.

**Spec/plan**: `docs/plans/2026-08-18-azure-keyvault-parity-audit.md`
(Critical Finding #8), `docs/superpowers/plans/2026-08-18-security-short-term-fixes.md`
(Task 5).

---

### B19 — Any Key Vault Data Access Administrator could grant itself, Purge Operator, or Certificate User

**Status**: Fixed in commit `ccdcb3d`; `4b4d0d1` fixed a follow-up where the
new `ErrRoleNotGrantable` rejection surfaced as HTTP 500 instead of 403 in
`createRoleAssignment` (the handler didn't map the sentinel, so it fell
through to `SetInternalError`)
**Severity**: High — Data Access Administrator exists specifically to
delegate role management *without* also granting data-plane access or the
ability to escalate to it; without this restriction a holder could grant
themselves Purge Operator/Certificate User or grant another principal a
second Data Access Administrator, defeating the role's entire purpose
**File**: `internal/services/authorization/role_assignment_service.go`,
`api/role_assignments.go`, `cmd/vault-access/grant.go`

**Root cause**: `RoleAssignmentService.AssignRole` applied the same
authorization check regardless of *which* role was being granted or by whom
— any caller who passed `CanManageRoleAssignments` (global admin, or Data
Access Administrator in that vault) could grant any role, including
`Key Vault Data Access Administrator`, `Key Vault Purge Operator`, and
`Key Vault Certificate User`. Azure's real ABAC restricts Data Access
Administrator from granting those three roles; RocketVault had no equivalent
restriction.

**What was fixed**: `AssignRoleInput` gained `CallerIsGlobalAdmin bool`, set
by both call sites (`api/role_assignments.go`'s `createRoleAssignment`,
`cmd/vault-access/grant.go`) from the same `common.HasRequiredRole(role,
string(model.RoleAdmin))` check `CanManageRoleAssignments` already performs.
`AssignRole` now rejects granting any role outside the
`nonAdminGrantableRoles` allow-list — which deliberately excludes
`RoleKeyVaultDataAccessAdministrator`, `RoleKeyVaultPurgeOperator`, and
`RoleKeyVaultCertificateUser` — with the new sentinel `ErrRoleNotGrantable`,
unless `CallerIsGlobalAdmin` is true. Five new tests in
`internal/services/authorization/role_assignment_service_test.go` pin both
the restriction and the global-admin bypass.

**Known residual gap**: the restriction is enforced by `AssignRole` only —
`RevokeAssignment` has no equivalent `CallerIsGlobalAdmin`-style check, so a
non-global-admin Data Access Administrator can *revoke* a Purge
Operator/Certificate User/Data Access Administrator assignment even though
they cannot *grant* one. Tracked separately as B21 below; deliberately
deferred, not an oversight (see the comment on `nonAdminGrantableRoles`).

**Spec/plan**: `docs/plans/2026-08-18-azure-keyvault-parity-audit.md` (Access
control finding F1), `docs/superpowers/plans/2026-08-18-security-short-term-fixes.md`
(Task 6).

---

### B20 — Per-item purge protection was dead code for secrets, keys, and certificates

**Status**: Fixed in commits `1e24095` (secrets), `986fc07` (keys), `d9a6136`
(certificates), plus three follow-ups from the same-day final review:
`16c1fa8` (the retry layer wrapped inner errors with `%v`, severing the
`errors.Is` chain, so a purge blocked by `ErrSecretPurgeProtected` surfaced
as HTTP 500 instead of 403 whenever `retry.database.enabled` — the default
— was true; changed to `%w`, and the vault-protection read now fails closed,
i.e. blocks the purge, if the read itself errors), and `68a52d8` (restoring a
secret/key/certificate via `Restore*` dropped its `purge_protection` flag —
repository `Create` doesn't write that column — so a backup taken while
protected restored unprotected; each `Restore*` now re-applies the decoded
entity's flag via `SetPurgeProtection` after create; also reworded the three
sentinel messages and hand-copied HTTP 403 literals in
`api/errors_{secret,key,certificate}.go`, which read as item-only despite
covering both item- and vault-level blocks).
**Severity**: High — an operator who enabled purge protection, expecting
Azure's guarantee that no contained object can be purged early, got no actual
protection for any secret, key, or certificate; a false sense of security for
exactly the compliance/data-loss-prevention scenario purge protection exists
for
**File**: `internal/repositories/{secret,key,certificate}_repository.go`,
`internal/services/{secrets,keys,certificates}/*_service.go`,
`model/{secret,key,certificate}.go`,
`api/{secrets,keys,certificates}.go`, `api/errors_{secret,key,certificate}.go`,
`cmd/{secrets,keys,certificates}/{create,update}.go`,
`internal/container/service_container.go`

**Root cause**: The `purge_protection` DB column, each repository's
`SetPurgeProtection` method, and the enforcement check inside
`PurgeSecret`/`PurgeKey`/`PurgeCertificate` all existed, but no API field,
service method, or CLI flag ever set the flag to `true` — it was unreachable
plumbing. Even where enforcement existed, only the background auto-purge
scheduler honored it; the manual `DELETE .../purge` path never checked it for
keys/certificates, and secrets didn't have the check wired for manual purge
at all. Vault-level purge protection also did not cascade to protect
contained items, only the vault itself.
`.claude/azure-keyvault-parity.md:177` stated "✅ (per-key + per-vault)",
which was true for per-vault but false for per-key.

**What was fixed**: For each resource type — `PurgeProtection *bool` added
to the service-layer create/update DTOs and the HTTP DTOs
(`purge_protection` JSON field, `nil` = no explicit value, matching the
existing `Enabled *bool` convention); a `--purge-protection` CLI flag on
`create`/`update`, gated by `cmd.Flags().Changed(...)`; each repository's
`Purge*` protection check now returns a shared sentinel
(`repositories.ErrSecretPurgeProtected`/`ErrKeyPurgeProtected`/
`ErrCertPurgeProtected`, `internal/repositories/purge_protection_errors.go`)
instead of a bare error, mapped to HTTP 403 in each `api/errors_*.go`; and
each service's `Purge*` method gained a vault-level cascade check via an
optional `VaultRepository` — if the containing vault has `PurgeProtection`
enabled, the purge is refused even if the item itself doesn't have the flag
set. New tests per resource type cover both the create/update wiring and the
vault-level cascade block.

**Spec/plan**: `docs/plans/2026-08-18-azure-keyvault-parity-audit.md`
(Critical Finding #2), `docs/superpowers/plans/2026-08-18-security-short-term-fixes.md`
(Tasks 7–9).

---

### B21 — `RevokeAssignment` does not enforce the Data Access Administrator grant restriction

**Status**: Fixed in commit `662781e`
**Severity**: Medium — narrower than B19: exploiting it requires the caller
to already hold Data Access Administrator in the vault (itself a
sensitive, deliberately-restricted grant), and the effect is revoking an
assignment rather than escalating privilege via a new grant
**File**: `internal/services/authorization/role_assignment_service.go`,
`api/role_assignments.go`, `cmd/vault-access/revoke.go`

**Root cause**: B19's fix restricted which roles `AssignRole` will grant for
a non-global-admin caller via `nonAdminGrantableRoles` and
`AssignRoleInput.CallerIsGlobalAdmin`. `RevokeAssignment`'s signature carried
no equivalent caller-authority flag, so it did not consult that allow-list.
A non-global-admin Data Access Administrator could grant only the allow-listed
roles, but could revoke *any* role assignment in their vault — including
another principal's `Key Vault Data Access Administrator`, `Key Vault Purge
Operator`, or `Key Vault Certificate User` grant.

**What was fixed**: `RevokeAssignment` gained a `callerIsGlobalAdmin bool`
parameter, mirroring `AssignRoleInput.CallerIsGlobalAdmin`, and now applies
the same `nonAdminGrantableRoles` allow-list to the assignment being revoked
— same shape as the `AssignRole` check, applied to the role being revoked
rather than the role being granted. Both call sites compute the flag the
same way `AssignRole`'s callers already do
(`common.HasRequiredRole(role, string(model.RoleAdmin))`):
`api/role_assignments.go`'s `deleteRoleAssignment` (which now also maps
`ErrRoleNotGrantable` to HTTP 403, mirroring the grant path) and
`cmd/vault-access/revoke.go` (which previously didn't even fetch the
caller's account role). Six `RoleAssignmentService` test doubles across the
authorization/middleware/api/cmd test suites were updated to the new 4-arg
signature. New tests: `TestRevokeAssignment_NonAdminCannotRevoke{DataAccessAdministrator,PurgeOperator,CertificateUser}`,
`TestRevokeAssignment_NonAdminCanRevokeOrdinaryRole`,
`TestRevokeAssignment_GlobalAdminCanRevokeAnyRole`
(`internal/services/authorization`), `TestRoleAssignments_RevokeDeniedRoleNotGrantable_Returns403`
(`api/role_assignments_test.go`), and `TestVaultAccessRevoke_PassesNonAdminCallerFlag`
(`cmd/vault-access/authz_test.go`).

**Spec/plan**: `docs/plans/2026-08-18-azure-keyvault-parity-audit.md` (Access
control finding F1 — this residual is called out under B19 above, not a
separate audit finding), `internal/services/authorization/role_assignment_service.go`'s
own comment on `nonAdminGrantableRoles`.

---

### B22 — `PurgeVault`'s bulk cascade-delete ignores per-item purge protection

**Status**: Fixed in commit `74dfab8`
**Severity**: High — before B20, this gap was inert because `purge_protection`
could never be set to `true` on any secret/key/certificate; B20 made the flag
real and settable, which made this a live, reachable bypass: purging a vault
silently destroyed every contained item regardless of its individual
purge-protection flag, the exact guarantee B20 just added for the
single-item purge path
**File**: `internal/repositories/secret_repository.go`'s `PurgeVaultContents`
(and the equivalent `key_repository.go`/`certificate_repository.go` methods),
`internal/services/vaults/cascade_adapter.go`, `internal/services/vaults/vault_service.go`,
`api/vault.go`

**Root cause**: `VaultService.PurgeVault` cascades to
`cascadeAdapter.PurgeVaultContents`, which calls each resource repository's
`PurgeVaultContents(ctx, vaultID)`. Those methods run an unconditional
`DELETE FROM secrets/keys/certificates WHERE vault_id = ?` with no
`purge_protection` check at all — by design, per the method's own comment,
to avoid stranding orphaned rows once the containing vault is gone. That
design predates B20; it was never revisited once per-item purge protection
became settable.

**What was fixed**: Took fix-sketch option (a) — `PurgeVault` now refuses to
purge a vault that still contains any item with `purge_protection = true`,
mirroring Azure's "cannot purge while it still contains protected items"
semantics; the caller must purge or wait out those items individually
first. Added `CascadeRepository.HasProtectedContent(ctx, vaultID) (bool,
error)`, backed by a `HasProtectedContent` method on each of
`SecretRepository`/`KeyRepository`/`CertificateRepository` — following the
existing `PurgeVaultContents` convention, added only to the concrete types,
not their exported `*RepositoryInterface`, to avoid rippling to every mock
across the codebase. `PurgeVault` calls it after the vault's own
`PurgeProtection` check and before `s.repo.Purge`, and **fails closed**: if
the check itself errors, the purge is refused rather than risking a bypass
because an item's status couldn't be read (same posture as B20's
`16c1fa8` follow-up). The new sentinel `ErrVaultContentsPurgeProtected` is
mapped to HTTP 400 in `api/vault.go` alongside the existing
`ErrVaultPurgeProtected`/`ErrDefaultVaultProtected` cases. New tests:
`TestSecretRepository_HasProtectedContent`/`TestKeyRepository_HasProtectedContent`/
`TestCertificateRepository_HasProtectedContent`,
`TestPurgeVault_RefusesWhenContentsProtected`/
`TestPurgeVault_ContentsProtectionCheckError_FailsClosed`
(`internal/services/vaults`), and `TestPurgeVault_RefusesWhenContentsProtected`
(`api/vault_test.go`).

**Spec/plan**: `docs/plans/2026-08-18-azure-keyvault-parity-audit.md`
(Critical Finding #2 row and "Remediation Update — Short-term Fixes
(2026-08-18)" section).

---

### B23 — Upgrading an existing database with a pre-`vault_id` `key_rotation_policies`/`rotation_policies` table crashed on startup

**Status**: Fixed in commit `f1d3d41`
**Severity**: High — any real, already-deployed database created before commit
`57bfa2b` (2026-08-17) could never start again after upgrading past it, and
the resulting failure mode was a nil-pointer panic on the first DB query of
any command (e.g. `users login`), not a clean error
**File**: `internal/db/db.go` (`createOptimizedSchema`), `cmd/root.go`
(`persistentPreRun`)

**Root cause (two independent bugs compounding)**:
1. Commit `57bfa2b` ("feat(db): add vault_id to rotation_policies and
   key_rotation_policies") added `vault_id` to both tables in two places:
   correctly in `migrateSchema` (`ALTER TABLE ... ADD COLUMN`, then
   `CREATE INDEX` *after* the ALTER — idempotent, safe on upgrade), and also
   in `createOptimizedSchema`, the fresh-install schema that runs *before*
   `migrateSchema` inside `SetupSchema`. There, `CREATE TABLE IF NOT EXISTS`
   is a safe no-op against a pre-existing old-shaped table, but the
   `CREATE INDEX ... (vault_id)` immediately following it in the same batch
   is not a no-op — it fails with `no such column: vault_id` against exactly
   that table shape. Since `createOptimizedSchema` runs first and its error
   aborts `SetupSchema`, `migrateSchema`'s correct fix for this never got a
   chance to run. This is the identical failure class already identified and
   avoided for `audit_logs`'s enriched-column indexes (see the comment at the
   end of `createOptimizedSchema`'s SQL block) — just not applied
   consistently to `key_rotation_policies`/`rotation_policies` when they got
   the same treatment. The regression test added in the same commit
   (`rotation_vault_scope_migration_test.go`) tested `migrateSchema` in
   isolation and `SetupSchema` only against a *fresh* database — never the
   real call path (`SetupSchema`) against an *old-shaped* one, so it couldn't
   catch this.
2. `cmd/root.go`'s `persistentPreRun` discarded `InitializeDB()`'s error
   (`//nolint:errcheck,gosec`). With the DB-init error above, execution
   continued with `database.GetDB()` returning `nil`, which
   `container.NewServiceContainer` threaded into every repository as a nil
   `*db.Conn` (its nil-guard was written assuming this only happens on the
   unit-test path). Any command reached deep into a DB call before crashing
   with a nil-pointer `SIGSEGV`, not a clean error — e.g. `users login`
   authenticates, logs "Starting user authentication," then panics inside
   `UserRepository.ReadByUsername`.

**What was fixed**:
1. Removed the two unsafe `CREATE INDEX ... (vault_id)` statements from
   `createOptimizedSchema` for `key_rotation_policies` and
   `rotation_policies` — both indexes are already correctly created in
   `migrateSchema`, after the ALTER TABLE, for both fresh and upgraded
   databases. New test `TestSetupSchema_UpgradesOldShapeRotationPolicies-
   WithoutError` (`internal/db/rotation_vault_scope_migration_test.go`)
   exercises the real `SetupSchema` call path against an old-shaped database
   and pins that this can't regress; confirmed it fails with the exact
   reported error (`no such column: vault_id`) against the pre-fix code.
2. `persistentPreRun` now checks `InitializeDB()`'s error and aborts with
   `fmt.Errorf("database initialization failed: %w", err)` for any command
   that isn't in the `context`/cobra-builtin exemption already used by the
   adjacent remote-target guard (those are documented no-DB/local-only paths
   and must keep working with no database configured at all, e.g.
   `rocketvault context list` before `.rocketvault.yaml` exists). New test
   `TestPersistentPreRun_DatabaseInitFailure_NonExemptCommand_ReturnsClean-
   Error` (`cmd/root_test.go`) pins that a DB-needing command now fails
   cleanly instead of reaching a later nil-pointer panic.

**Effect for existing (real, not test) databases**: with fix 1 alone, a
database in the pre-`vault_id` shape now upgrades in place on next startup —
no data loss, no manual intervention. Fix 2 is defense in depth so any
*future* DB-init failure (a different stale-schema case, a permissions
issue, a full disk) surfaces as a clean error instead of the same class of
panic.

**Reported by**: a real user hitting this on `users login` against an
existing local database, not discovered via review — see conversation
history for the original panic output.

---

### B24 — `POST /keys` rejected the P-256K curve despite full support elsewhere

**Status**: Fixed
**Severity**: Medium — a real, working capability was unreachable through the
only HTTP-facing way to create keys; the CLI and service layer already
supported it, so this was a REST-API-specific regression, not a missing
feature
**File**: `internal/validation/key_validation.go`

**Root cause**: `ValidateKeyCreate`'s curve field used
`validation.In("P-256", "P-384", "P-521")` — an allowlist that predated
P-256K support and was never updated when it was added elsewhere.
`api/keys.go`'s `createKey` handler calls this validator (line 282) *before*
its own, already-correct four-curve check at line 358
(`req.Curve != "P-256" && ... && req.Curve != "P-256K"`), so the validator's
`400 Curve: must be a valid value.` fired first and the handler's own check
never got a chance to run. `KeyService.CreateECDSAKey` (the service layer)
also independently allowed P-256K, and the CLI (`rocketvault keys create
--curve P-256K`) worked because it calls `KeyService` directly and never
goes through this HTTP validator at all — so the bug was specific to the
`POST /keys` REST path. Found during the 2026-08-19 Azure parity audit
against `.claude/azure-keyvault-parity.md` §3, while re-verifying EC curve
support against the actual API surface rather than the service layer alone.

**What was fixed**: Added `"P-256K"` to the `validation.In(...)` allowlist in
`key_validation.go` (one line), plus its doc comment. Added a regression test
at the API layer (`TestCreateKey_ECDSA_P256K_Success_Returns201`,
`api/keys_crud_test.go`) asserting `POST /keys` with `curve: "P-256K"`
returns 201 — a unit test on the validator alone would not have caught the
original bug, since it's an interaction between two independent checks in
two different files. Added a unit case to `TestValidateKeyCreate`
(`internal/validation/validation_test.go`) for direct coverage of the
allowlist itself. Also updated the CLI's `--curve` flag help text
(`cmd/keys/create.go`), which listed only three curves despite the fourth
already working.

**Scope check performed, no other call site affected**: `ValidateKeyCreate`
has exactly one caller (`api/keys.go:282`). `ValidateKeyUpdate` has no
`Curve` field — key updates never change curve, so the update path was never
affected. Key rotation reuses the existing key's stored curve
(`KeyService.RotateKey`), not user input, so it was never affected either.

---

### B25 — `POST /keys` with `curve: "P-256K"` leaked an uncaught 500 on HSM-enabled instances

**Status**: Fixed
**Severity**: Medium — an information-disclosure-adjacent error-handling gap
(a raw internal error string reached the client) rather than a capability
gap; HSM-backed P-256K key creation was never actually supported and still
isn't — only the failure mode was wrong
**File**: `api/keys.go`, `api/errors_key.go`

**Root cause**: A direct follow-up to B24. Once `ValidateKeyCreate` allowed
`P-256K` through (B24's fix), `POST /keys {"curve":"P-256K"}` on an
HSM-enabled instance (`hsm.enabled: true`, this repo's own configured
default) reached `KeyService.CreateECDSAKey` → `PKCS11KeyProvider
.GenerateECDSAKey`, which correctly returns `crypto.ErrUnsupportedCurve`
(`internal/crypto/pkcs11_provider.go`'s `ecOID` map has no P-256K entry — no
PKCS#11 mechanism exists for it). But `createKey`'s error switch
(`api/keys.go`) only special-cased `crypto.ErrOctKeysRequireHSM` into a
clean 400 — every other error, including this one, fell through to
`c.SetInternalError(err)`, an uncaught HTTP 500 with the raw Go error text
(`"failed to generate ECDSA key: curve not supported by PKCS#11 provider:
P-256K"`) in the response body. The same `GenerateECDSAKey` call exists in
`KeyService.RotateKey` for `ES256K` keys, reached via the shared
`writeKeyError` helper (`api/errors_key.go`), which had the identical gap —
currently unreachable in practice (an HSM instance can never create the
P-256K key it would need to rotate), but the shared helper needed the same
fix for correctness. Found via live end-to-end verification while following
up on B24 against `.claude/azure-keyvault-parity.md` §3 — a unit test on the
validator alone (B24's fix) would not have caught this, since it's a
downstream error-mapping gap in a completely different file.

**What was fixed**: Added a case for `crypto.ErrUnsupportedCurve` to both
`createKey`'s error switch (`api/keys.go`) and the shared `writeKeyError`
(`api/errors_key.go`), mapping it to a clean 400 with the message `curve: `
plus the underlying error text — mirroring the existing
`crypto.ErrOctKeysRequireHSM` precedent exactly. Added two regression tests:
`TestCreateKey_ECDSA_P256K_NoHSMMechanism_Returns400` and
`TestRotateKey_P256K_NoHSMMechanism_Returns400` (`api/keys_crud_test.go`),
both reproducing the exact error value and wrapping the real service layer
produces. HSM-backed P-256K key creation itself remains unsupported by
design (no PKCS#11 mechanism exists) — this fix corrects only the failure
mode, not the underlying capability gap.

**Scope check performed**: grepped every `GenerateECDSAKey` call site (two:
`CreateECDSAKey` and `RotateKey`, both in `KeyService`) and every consumer of
their errors (`createKey`'s inline switch and `writeKeyError`, respectively)
— both are now covered. `crypto.ErrUnsupportedAlgorithm`, a sibling PKCS#11
sentinel for algorithm (not curve) mismatches, was checked separately and
found to already be properly wrapped into a service-level
`keyservices.ErrUnsupportedAlgorithm` and mapped to 400 in six handlers — no
gap there.

---

### B26 — Rotating a key permanently stranded every pre-rotation ciphertext and signature

**Status**: Fixed
**Severity**: High — silent, permanent data loss: any secret encrypted, any
signature produced, or any key wrapped before a rotation became
undecryptable/unverifiable/unwrappable forever, with no error at rotation
time to warn the caller
**Files**: `internal/repositories/key_repository.go`,
`internal/services/keys/crypto_service.go`, `internal/services/keys/key_service.go`,
`api/keys.go`, `api/errors_key.go`, `internal/backup/item_backup.go`, `model/key.go`

**Root cause**: `KeyService.RotateKey` (`internal/services/keys/key_service.go`)
always archived the pre-rotation key material into `key_versions.value` before
overwriting `keys.value` with the newly generated material — the write path
was correct and had been since `key_versions` was introduced. But nothing on
the read side ever used it: `model.KeyVersion` had no `Value` field,
`KeyRepository.ListVersions` deliberately selected only `version, created_at`
("Raw key material (value) is not returned" per its own doc comment), and none
of the six crypto operations — `Sign`/`Verify`/`Encrypt`/`Decrypt`/`WrapKey`/
`UnwrapKey` in `internal/services/keys/crypto_service.go` — had any way to
request a version; every one of them always resolved to `key.Value`, the
*current* row, unconditionally. The archived material was sitting in the
database, correctly encrypted, and permanently unreachable. Practical impact:
rotate a key once, and every ciphertext, wrapped key, or signature produced
before that rotation could never be decrypted, unwrapped, or verified again —
a real, silent data-loss bug with no error raised at rotation time to warn
the caller it was about to happen. Found via `.claude/azure-keyvault-parity.md`
§2 gap analysis against Azure Key Vault, which keeps every key version
independently addressable and usable indefinitely.

**Bundled bug found during design, fixed in the same pass**:
`resolveKeyMaterial` (`internal/services/keys/crypto_service.go`) cached
decrypted PEM material keyed on `(key.ID, 0)` — the version component of the
cache key was hardcoded to `0`, not derived from the material actually being
resolved, even though `internal/keycache`'s `Get`/`Set` already took a real
`version int` parameter that nothing ever populated correctly. Harmless
before this fix, since only one version (the current one) was ever resolved
per key. Had the version-addressing fix below shipped without also fixing
this, a second version's material would have been served from the first
version's stale cache entry (or vice versa) on any two-versions-in-a-row
lookup — a silent wrong-plaintext / wrong-signature bug, worse than the
original gap because it would fail without even raising a not-found error.

**What was fixed** (plan:
`docs/superpowers/plans/2026-08-19-key-version-addressability.md`, design:
`docs/superpowers/specs/2026-08-19-key-version-addressability-design.md`,
commits `78ad152..f03957a`):
- `KeyRepository` gained `ReadVersionValue`/`GetVersion`/`ListVersionRecords`
  to read archived `key_versions` rows (material and metadata), authorized
  against the key's owner, matching the existing `ListVersions` idiom exactly.
  A new `model.KeyVersionRecord` internal-only type carries material for
  backup use; the existing HTTP-facing `model.KeyVersion` still never gains a
  `Value` field, so API responses can't leak material even by future mistake.
- All six crypto service request/result types
  (`SignRequest`/`VerifyRequest`/`EncryptRequest`/`DecryptRequest`/
  `WrapKeyRequest`/`UnwrapKeyRequest` and their `*Result` counterparts) gained
  an optional `Version int` — `0`/omitted resolves to the current version,
  unchanged from prior behavior; any other value resolves via the new
  repository methods. Same addition on the six HTTP request/response types in
  `api/keys.go`, as a `"version"` JSON field (`omitempty` on the request,
  always present on the response so a caller who omitted it can discover what
  "current" resolved to).
- `resolveKeyMaterial`'s cache key changed from the hardcoded `(key.ID, 0)` to
  `(key.ID, resolvedVersion)` — the fix for the bundled cache bug above.
- New `GET /keys/{key_id}/versions/{version}` route (flat + vault-scoped),
  backed by a new `KeyService.GetKeyVersion`, mirroring the existing
  `ListKeyVersions` authorization shape — closes the read-side asymmetry
  against secrets, which already had `GET /secrets/{id}/versions/{version}`.
  `repositories.ErrKeyVersionNotFound` (new sentinel) maps to a clean 404 in
  both the six crypto handlers' inline error switches and the shared
  `writeKeyError` helper.
- `internal/backup/item_backup.go`'s shared `backupEnvelope` gained an
  additive `Versions []model.KeyVersionRecord` field (`omitempty`), populated
  by `BackupKey` via `ListVersionRecords` and replayed by `RestoreKey` via
  `CreateVersion` under the restored key's new ID. Purely additive to the
  envelope — a pre-fix backup blob (no `versions` field) still decodes and
  restores exactly as before, just without version history, so this is
  backward compatible with every backup taken before this fix. Without this
  half of the fix, a rotated key's version history would have silently been
  lost on any backup/restore cycle, reintroducing the exact bug this fix
  closes via a different path than rotation.
- OCT (symmetric, HSM-only) keys are unaffected: `RotateKey` has no case for
  `model.KeyTypeOCT` and OCT keys cannot be rotated at all, so there is no
  multi-version OCT case to fix.

**Two follow-ups from the whole-branch review, fixed in the same body of
work**:
- `KeyService.ListKeyVersions` now synthesizes the implicit version-1 entry
  when `key_versions` is empty, so `GET /keys/{id}/versions` no longer reports
  an empty history for a never-rotated key whose version 1 both
  `GET /keys/{id}/versions/1` and every crypto operation happily resolve. The
  synthesized entry is timestamped by the key's own `CreatedAt`, matching
  `ReadVersionValue`/`GetVersion`'s existing fallback. `RotateKey` deliberately
  still calls the raw `KeyRepository.ListVersions`, since its version-numbering
  math needs the true zero-row count.
- New `KeyRepository.CurrentVersion` — a single `COALESCE(MAX(kv.version), 1)`
  aggregate over a LEFT JOIN from `keys` — replaces the full `ListVersions` row
  scan that `cryptoService.currentVersionNumber` was running on *every* crypto
  operation just to compute one number. The LEFT JOIN direction is load-bearing:
  an INNER JOIN from `key_versions` returns zero rows for a never-rotated key
  rather than a row with a NULL aggregate, which would defeat the `COALESCE`
  fallback to 1.

**Left open, tracked as a fast-follow, not a regression**: all four crypto CLI
commands — `rocketvault keys sign` (`cmd/keys/sign.go`), `keys verify`
(`cmd/keys/verify.go`), `keys wrap` (`cmd/keys/wrap.go`), and `keys unwrap`
(`cmd/keys/unwrap.go`) — still call their `CryptoService` method with
`Version` left unset (always current), and none exposes a `--version` flag.
REST is the only way to address an archived version today. (There are no
`keys encrypt`/`keys decrypt` CLI commands at all, so those four are the
complete set.) Flagged explicitly in the design's "Not in scope" section
rather than silently deferred. Also noted but not fixed, as pre-existing and
unrelated gaps in the purge path: `KeyRepository.PurgeKey` never destroys
PKCS#11 HSM token objects for the current or any archived version on purge;
and it deletes only the `keys` row, relying on `ON DELETE CASCADE` to remove
the matching `key_versions` rows — but this project runs SQLite with
`foreign_keys` left off (`internal/db/db.go` never issues
`PRAGMA foreign_keys = ON`), so on SQLite deployments a purged key leaves its
archived `key_versions` rows, encrypted material and all, orphaned in the
database. Both are candidates for their own future entries here if they need
to be addressed.

### B27 — Rotation policy's `expiry_days` lifetime action was stored but never acted on

**Status**: Partially fixed
**Severity**: Low — a documented, non-functioning policy field, not a
security or data-loss issue; an operator configuring `expiry_days` got no
error, just silent non-enforcement
**Files**: `internal/services/keys/key_service.go`,
`internal/services/keys/keys_edge_test.go`

**Root cause**: `UpsertKeyRotationPolicy` (`api/key_rotation_policy.go` →
`internal/services/keys/key_service.go`) persisted and echoed back both
`expiry_days` and `notify_before_expiry_days`, but `RotateKey` never read
either — `Key.ExpiresAt` was left exactly as it was before rotation, forever,
regardless of what a policy's `expiry_days` said. Azure's Notify lifetime
action has two halves: stamping an expiration on the rotated version, and
sending a near-expiry notification. Neither had any implementation behind it.
Found via `.claude/azure-keyvault-parity.md` §2's "Get/Set rotation policy" row.

**What was fixed** (commit `1161fa5`): `RotateKey` now looks up the key's
rotation policy via the already-injected `policyRepo` and, if the policy is
`Enabled` with `ExpiryDays > 0`, stamps `existing.ExpiresAt = now +
ExpiryDays` before the existing `KeyRepository.Update` call — no new
repository method needed, since `Update`'s SQL already writes `expires_at`
(`UpdateKey` already lets callers set it directly). Applies uniformly to
every rotation, scheduled or manual, since both paths go through the same
`RotateKey`. `policyRepo` is nil-guarded (most `keyService` test instances,
and any future minimally-constructed caller, don't set it — matches the
existing `vaultRepo` optional-dependency convention already used in
`PurgeKey`), and a key with no policy configured — the common case — rotates
exactly as before. A genuine repository error during the policy lookup (not
"no policy configured", which is `sql.ErrNoRows` and expected) fails the
whole rotation rather than silently skipping the stamp.

**Deliberately not fixed — a separate, larger effort**:
`notify_before_expiry_days` (the actual near-expiry *notification*) is
untouched. RocketVault has no notification delivery mechanism anywhere in the
codebase — `internal/services/secrets/scheduler_service.go`'s `sendReminder`
is a logging-only placeholder (its own comment: "In a real implementation,
this would send email/SMS notifications"), and
`internal/services/secrets/expiration_service.go`'s `ExpirationService` is
unwired, unreachable dead code (`NewExpirationService` is never called from
`internal/container/` or any `cmd/` bootstrap). Building real delivery (at
minimum a generic webhook) is RocketVault's own roadmap item — see
`.claude/roadmap-azure-parity-and-beyond.md`'s Phase 3 "native
webhook/notification system" entry — and was explicitly scoped out of the
original rotation-scheduler work for the same reason
(`docs/superpowers/specs/2026-08-18-rotation-policy-scheduler-design.md`
§11). Tracked as its own future design/plan, not a follow-up here.

**Also out of scope**: secrets. `model.RotationPolicy` (the secrets-side
policy) has no `expiry_days` field at all — only `ReminderDays`/`AutoRotate`,
an entirely separate, non-shared schema from keys' `KeyRotationPolicy`.
Adding secret-side expiry stamping would be a schema change and its own
decision, not implied by this fix.

**2026-08-20 update — storage/configuration layer shipped, B27 stays open**:
A per-vault webhook *storage and configuration* layer now exists on
`feat/vault-webhook-config` (`docs/superpowers/specs/2026-08-19-vault-webhook-config-design.md`):
table `vault_webhook_configs` (`internal/db/db.go`), `model.VaultWebhookConfig`
(`model/vault_webhook.go`), `internal/repositories/vault_webhook_repository.go`,
`internal/services/vaults/webhook_service.go`
(`VaultWebhookService`/`UpsertWebhookRequest`), the HTTP routes
`PUT`/`GET`/`DELETE /vaults/{name}/webhook` (`api/vault_webhook.go`,
`api/vault.go`), and a `rocketvault vault-webhook set|get|delete` CLI
(`cmd/vault-webhook/`). The signing secret is server-generated, encrypted at
rest, and returned in plaintext exactly once — on create or rotate via `set`
— never again afterwards (`GET`'s response schema has no `signing_secret`
field at all).

This is configuration only. **B27 remains open.** Nothing sends a
notification yet — this sub-project deliberately built no delivery mechanism
of any kind: no outbound HTTP call, no sender, no payload schema. The
paragraph above this one, stating RocketVault "has no notification delivery
mechanism anywhere in the codebase," is still accurate about *delivery* —
what changed is that a notification now has somewhere to be configured to go
*to*, not a way to get there. `notify_before_expiry_days` still has no
effect. The remaining work is split into its own sub-projects, not follow-up
tasks here: the delivery primitive (which will make the first real outbound
HTTP call and own the payload schema), keys' near-expiry sweep (reading
`notify_before_expiry_days` off `KeyRotationPolicy` and firing the delivery
primitive), secrets' `sendReminder` wiring (replacing the logging-only
placeholder in `internal/services/secrets/scheduler_service.go`),
certificates' expiry-warning wiring, and user-facing docs
(`docs/usage-guide.md`, deferred until the chain is usable end-to-end).

---

### B28 — Item backup gated on ownership, and unscoped underneath it

**Status**: Fixed 2026-08-19
**Severity**: High — the visible half refused every legitimately-authorized
non-owner, a real Azure parity gap; the hidden half meant the ownership check
was the *only* thing stopping a caller from backing up an item they owned in
a vault other than the one their request was authorized against
**Files**: `internal/backup/item_backup.go`, `api/backup_item.go`

**Root cause**: `ItemBackupService.BackupKey` read the target key via
`model.NewAdminScope(userID)` — a scope with no predicate at all — and then
separately compared `key.UserID == caller`, returning `ErrForbidden` (→ HTTP
403) for anyone else; the method's own comment said as much: "The read itself
is unchecked (admin scope); the explicit ownership check below is the actual
gate." Azure's Crypto User role grants `keys/backup/action` with no ownership
concept whatsoever, so this refused every non-owner who legitimately held
`ActionKeysBackup` — a real parity gap. `BackupSecret` and `BackupCertificate`
carried the identical gate. Before this fix none of the three methods even
took a `vaultID` parameter, so the ownership comparison was the *only* code
confirming the named item belonged to the caller at all — nothing tied the
read to the vault the caller's request was authorized against. A caller who
owned a key in vault A could back it up via a request authorized only for
vault B, since the admin-scoped read would find the key by ID regardless of
vault and the ownership check passed independently of which vault was in
play. Deleting the ownership check to close the parity gap — the obvious
fix — would, on its own, have left that cross-vault read open.

**What was fixed** (plan:
`docs/superpowers/plans/2026-08-19-item-backup-vault-scoped-authz.md`): all
three `Backup*` methods now take the request's authorized `vaultID`
(resolved by `vaultIDFromRequest`, the same rule the three `Restore*` methods
already followed per B15) and read with `model.NewVaultScope(vaultID,
userID)` instead of an admin-scoped read plus an ownership comparison — the
repository's scope predicate is now the sole enforcement point, and an
out-of-scope ID reports 404, matching every other scoped resource route.
`BackupKey` also switched `ListVersionRecords`'s second argument from the
caller's ID to `key.UserID` (the key it just read): that query joins
`k.user_id`, so passing the caller's ID was safe only while caller-equals-
owner was guaranteed, and once a non-owner can legitimately back up a key it
would have returned zero rows and silently dropped the key's rotation
history from the blob — reintroducing the exact loss B26 closed, through a
different path. `backup.ErrForbidden` and the three now-unreachable
`errors.Is(err, backup.ErrForbidden)` branches in the restore handlers
(`api/backup_item.go`) were also deleted; the three backup handlers had
already lost theirs in the same body of work, and no `Restore*` method had
ever produced the sentinel in the first place.
`TestBackupKeyNonOwnerInSameVaultSucceeds`, `TestBackupKeyReadsWithVaultScope`,
`TestBackupSecretNonOwnerInSameVaultSucceeds`, and
`TestBackupCertificateNonOwnerInSameVaultSucceeds`
(`internal/backup/backup_edge_test.go`, `internal/backup/item_backup_test.go`)
pin the fix.

**Superseded by**: F2 (below) — the `user_id` parameter itself was removed
from `ListVersionRecords` and its four sibling version methods on 2026-08-20.

---

### B29 — Secret backup silently discarded every archived version

**Status**: Fixed 2026-08-20.
**Severity**: High — silent, permanent data loss: a secret with ten
historical versions backed up and restored as one, with no error and no
warning to the caller.
**Files**: `internal/backup/item_backup.go`, `model/secret.go`,
`internal/backup/item_backup_test.go`

**Root cause**: `ItemBackupService.BackupSecret` ended
`return encodeBlob("secret", id.String(), secret, nil)`. The `nil` was the
versions argument. `model.Secret` carries a `Version` *number*, which made
the blob look complete, but the historical values live in the separate
`secret_versions` table the blob never read.

**Why it survived**: the identical defect on the key path was found and
fixed on 2026-08-19 (§ B26), but that fix was scoped to keys; `BackupSecret`'s
`nil` was left in place and only became conspicuous once `BackupKey` was
explicit about carrying history. Nothing tested for the absence.

**What was fixed** (commits `34ffee1`, `284a60b`, `8327ab7`):
- `34ffee1` generalized the backup blob envelope from a keys-only
  `[]model.KeyVersionRecord` parameter to a `blobVersions{Key, Secret}`
  struct, adding a new additive `secret_versions` JSON field (`omitempty`)
  alongside the existing `versions` field.
- `284a60b` injected `SecretVersionRepositoryInterface` into
  `ItemBackupService`; `BackupSecret` now calls `GetVersions` and puts the
  result in the blob's `Secret` field. `model.SecretVersion` gained the same
  sensitivity-warning comment `model.KeyVersionRecord` already carried.
- `8327ab7` made `RestoreSecret` replay those versions under the new
  secret's ID: each row gets a fresh `uuid.New()` primary key
  (`secret_versions.id` is a PRIMARY KEY, and the source secret usually
  still exists, so reusing the blob's IDs would collide) and the restoring
  caller's `UserID` (`secret_versions.user_id` is a real FK to `users`,
  enforced on PostgreSQL, so carrying the blob's original owner could
  reference a user absent from the target deployment).

**Security note**: a secret backup blob now carries every historical secret
value, so it is exactly as sensitive as a key backup blob — the response
body is a merely base64url-encoded, not encrypted, JSON envelope.

**Back-compat**: the new field is `omitempty` and additive, so blobs taken
before this change decode with a nil slice and restore unchanged — pinned by
`TestRestoreSecret_OldFormatBlob_NoVersionsField`.

**Pinned by**: `TestBackupSecret_CarriesVersionHistory`,
`TestBackupRestoreSecret_CarriesVersionHistory`,
`TestRestoreSecret_OldFormatBlob_NoVersionsField`
(`internal/backup/item_backup_test.go`).

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

---

### F2 — Key-version repository queries carried a `user_id` filter that authorized nothing

**Status**: Fixed 2026-08-20 (commits `746bf91`, `44334b5`).
**Severity**: Low (architectural) — no runtime bug; the predicate could
never fail, but its presence as an apparent authorization check enabled the
ambiguity behind B28.
**Files**: `internal/repositories/key_repository.go`,
`internal/repositories/key_versions_test.go`,
`internal/services/keys/key_service.go`,
`internal/services/keys/crypto_service.go`,
`internal/backup/item_backup.go`.

**What it was**: `KeyRepository`'s five version methods — `ListVersions`,
`ReadVersionValue`, `GetVersion`, `ListVersionRecords`, `CurrentVersion` —
each took a `userID uuid.UUID` and filtered on a joined `keys.user_id`.
`ReadVersionValue` and `GetVersion` each additionally fell back to a second,
implicit-version-1 query directly against `keys` (for a never-rotated key
with zero `key_versions` rows), and that fallback query carried the same
`user_id` predicate.

**Why it authorized nothing**: all five methods are reachable only after
the caller has already read the parent key through a scoped `Read` (which
applies the real vault predicate), and every call site then passed *that
key's own owner ID* back in — never the caller's own. The predicate was
therefore satisfied by construction on every code path and could not fail,
while still reading like an access control.

**Why it was worth removing**: a parameter that looks like an authorization
control but is really "pass back the owner ID you just read" gives no
signal when it is passed the wrong value. B28 is exactly that bug:
`ItemBackupService.BackupKey` passed the *caller's* ID into
`ListVersionRecords`, which was correct only while an upstream ownership
check guaranteed caller == owner. Once that ownership check was slated for
removal to close a real Azure-parity gap, the argument would have silently
become wrong, and a non-owning caller's backup would have returned zero
version rows — dropping a rotated key's history with no error. B28's fix
(2026-08-19) worked around this by switching that one call site to pass
`key.UserID` instead; this refactor removes the parameter (and the
ambiguity) everywhere.

**Fix**: the `userID` parameter and its `user_id` predicate were dropped
from all five methods (`746bf91` for `ReadVersionValue`/
`ListVersionRecords`, `44334b5` for `ListVersions`/`GetVersion`/
`CurrentVersion`, the latter also fixing a third `ListVersions` call site in
`KeyService.RotateKey` that the plan's caller table had missed).
`CurrentVersion` also dropped its `LEFT JOIN keys k` entirely (corrected
during final review, 2026-08-20): the join was never load-bearing — an
ungrouped aggregate query always returns exactly one row regardless of join
type or how many rows match, so `COALESCE(MAX(version), 1)` against
`key_versions` alone already supplies the never-rotated fallback of `1`
without any join. The new contract matches the pre-existing
`SecretVersionRepositoryInterface`
(`internal/repositories/versioning_repository.go:18-28`), which has never
taken a user or scope parameter on any method, for the same reason: the
caller's scoped read of the parent secret is the only enforcement point.
`TestKeyVersions_ReadVersionValue_WrongOwner`, which asserted the retired
filter, was deleted — the argument it exercised no longer exists.

**Pinned by**: `TestVersionQueries_NotFilteredByOwner`,
`TestVersionMetadataQueries_NotFilteredByOwner`,
`TestCurrentVersion_NeverRotatedKeyStillReturnsOne`
(`internal/repositories/key_versions_test.go`).
