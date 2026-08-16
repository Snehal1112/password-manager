# Remove the HS256 JWT "Migration Window" Fallback — Design

**Date:** 2026-08-16
**Status:** Approved (design decision confirmed with the maintainer; do not re-litigate)
**Branch target:** `v-4.0.0`
**Finding:** H1 of `.claude/pentest-report-2026-08-16.md` — *"JWT forgery via HS256
'migration window' fallback + committed `jwt_secret` → full admin takeover."*
Confirmed live by exploitation and independently re-verified.

## Goal

Delete the legacy HS256 (symmetric HMAC) JWT verification path from RocketVault.
After this change, `jwtService.ValidateToken` accepts **only** tokens carrying a
`kid` header that resolves to a public key published by the configured
asymmetric `signing.SigningKeyProvider` (RS256/ES256). A token with no `kid` —
regardless of how correctly it is signed — is rejected.

This is a **clean removal**, not a hardening of the existing window. Nothing in
this spec attempts to fix `migrationDeadline` computation, add an absolute
deadline, or keep a switch that re-enables HS256.

## The vulnerability

Three facts combine into full administrative takeover for anyone who can read
this repository (including any historical clone, fork, or mirror):

1. **`ValidateToken` falls back to HS256 whenever `kid` is absent.**
   `internal/services/auth/jwt_service.go:152-166` peeks at the unverified
   header; if `kid == ""` it calls `validateHS256Fallback`
   (`jwt_service.go:197-222`), which verifies the token with
   `s.hs256SecretKey` — i.e. `[]byte(config.SecretKey)`, populated from
   `viper.GetString("jwt_secret")` in `internal/container/service_container.go:354`.

2. **The migration window never closes.** `NewJWTServiceWithProvider`
   (`jwt_service.go:65-82`) sets
   `svc.migrationDeadline = time.Now().Add(config.MigrationWindow)` **at service
   construction**. Since the service is constructed on every process boot, the
   `jwt.migration_window: "24h"` in `.rocketvault.yaml:16` restarts on every
   restart. The window is, in practice, permanently open.

3. **The HMAC key is public.** `jwt_secret` is a static literal committed to
   `.rocketvault.yaml:8` and present throughout git history (finding H4 of the
   same pentest report covers the config/git-history side, including rotation).
   With HS256, the verification key *is* the signing key — so a public
   verification key means anybody can mint tokens.

**Live proof (from the pentest run):** log in normally as a low-privilege user
(`role=user`) to obtain a real, non-revoked session `jti`; forge a token with no
`kid` header, `role: admin`, the correct issuer/audience, and that real `jti`;
sign it with the committed `jwt_secret`. `GET /api/v1/users/` returned **HTTP
200** with the full admin-only user list. Controls behaved correctly (random
`jti` → 401; wrong secret → 401), which confirms the *only* missing control is
the secrecy of the HS256 key.

`ValidateSession` (`internal/services/auth/authentication_service.go:225-283`)
compounds the impact by trusting the JWT's `role` claim rather than re-reading
the caller's role from the database — but that is a **separate** issue, see
"Explicitly out of scope" below.

## Why removal (not repair)

| Option | Verdict | Reason |
|---|---|---|
| Anchor `migrationDeadline` to a fixed absolute timestamp written once at upgrade time | Rejected | Adds config surface and an upgrade ritual to preserve a path that protects nothing (see next row). Still leaves a public-key HMAC verifier live for the duration. |
| Default `jwt.migration_window` to `0` and keep the code | Rejected | Leaves a foot-gun that re-arms full admin takeover with a single YAML line, and keeps the HS256 verifier in the binary. Fail-closed-by-config is weaker than fail-closed-by-construction. |
| **Remove the HS256 verification path entirely** | **Chosen** | `jwt.key_source` defaults to `os_store` (`internal/signing/provider.go:50-53`) and RS256/`os_store` is the only signing provider actually in use. This branch has never shipped a tagged release, so there is **no** population of legacy HS256 tokens in the wild that needs a transition. The fallback's own secret is public, so it can never be a trustworthy verification path anyway. The code protects zero real migrations and provides one complete authentication bypass. |

## Scope of the change

### 1. `internal/services/auth/jwt_service.go`

- `ValidateToken` (currently lines 152-166): when `kid` is empty, reject with an
  explicit error instead of calling the fallback. Log the rejected `alg` at warn
  level so forged-token attempts are visible in the audit trail.
- Delete `validateHS256Fallback` (lines 197-222) in full.
- Delete the `hs256SecretKey []byte` and `migrationDeadline time.Time` fields
  from `jwtService` (lines 38-40) and the block in `NewJWTServiceWithProvider`
  that populates them (lines 77-80).
- Delete `legacyJWTService` (lines 44-50) and its three methods (lines 250-332),
  plus the `NewJWTService` constructor (lines 84-98). Its `GenerateToken` is the
  only code in the repository that can *mint* an HS256 token; leaving it behind
  would leave the forgery primitive one call away and keep the tests that
  exercise it meaningful.
- Delete `SecretKey` and `MigrationWindow` from `JWTConfig` (lines 54, 58).
  Nothing reads them after the above.

`GenerateToken`, `validateAsymmetric`, `validateCommonClaims`, and `ParseToken`
on `jwtService` are **unchanged**. The `JWTService` interface itself is
unchanged — only the concrete symmetric implementation disappears.

### 2. `internal/container/service_container.go`

Today (lines 341-370) a failure to build the signing provider is a *warning*
that falls back to HS256:

```go
provider, err := signing.NewProvider(viperCfg, signingDeps)
if err != nil {
    c.logger.WithError(err).Warn("Failed to initialise asymmetric JWT signing provider, falling back to HS256")
    provider = nil
}
```

After this change the asymmetric provider is **mandatory**: a construction
failure aborts container initialisation with an error. This is safe in practice
because the default provider cannot fail — `NewOSStoreProvider`
(`internal/signing/os_store.go:59-93`) auto-generates an RSA-2048 key when the
keychain has no entry, and degrades to a PEM file and then to an in-memory key
rather than returning an error. The paths that *can* fail are all genuine
misconfiguration: an unknown `jwt.key_source`, `external_pki` with no key file,
or `self_pki` with missing dependencies. Failing startup on those is the correct
fail-closed behaviour; silently serving a forgeable token format is not.

`jwtConfig` loses its `SecretKey`/`MigrationWindow` entries, so
`viper.GetString("jwt_secret")` and `viper.GetDuration("jwt.migration_window")`
disappear from the Go code. **No Go-level startup validation requires
`jwt_secret` to be non-empty** — the only such check is the
`if jwtConfig.SecretKey == "" { return fmt.Errorf("JWT secret not configured …") }`
guard inside this same fallback branch (line 366), which is removed with the
branch. `bootstrap/`'s `ConfigurationValidator` never inspects `jwt_secret`
(verified by grep across `bootstrap/`, `config/`, `app/`, `cmd/`).

### 3. Config keys — deliberately *not* edited here

`.rocketvault.yaml` still contains `jwt_secret` (line 8) and
`jwt.migration_window` (line 16). Removing those committed values, and rotating
the leaked secret, belongs to **finding H4** and its own plan, which runs after
this one and references this change. After this change both keys are simply
unread by any Go code; a leftover value in YAML has no effect on behaviour.
`bootstrap/secrets_initializer.go:22` mentions `jwt_secret` only inside a
doc-comment example of the generic `ENV → viper key` mapping — that example is
illustrative, not a live mapping, and is left alone.

### 4. Tests

**Removed** (they assert the vulnerable behaviour, or exercise the deleted
symmetric service):

- `internal/services/auth/jwt_service_provider_test.go`:
  `TestJWTService_Provider_HS256Fallback_ActiveWindow` (asserts a forged-format
  token is *accepted*) and `TestJWTService_Provider_HS256Fallback_ExpiredWindow_Rejected`
  (asserts rejection only via the window, which no longer exists).
- `internal/services/auth/jwt_service_test.go`: both tests construct
  `NewJWTService`; their behaviour (expired rejected / valid accepted) is
  already covered for the asymmetric path by
  `TestJWTService_Provider_ExpiredToken_Rejected` and
  `TestJWTService_Provider_GenerateAndValidate_ES256`. The file is deleted.
- `internal/services/auth/auth_edge_cases_test.go`, "legacyJWTService" block
  (lines 122-225): four tests — `ParseToken`, `ParseToken_MalformedToken`,
  `ValidateToken_WrongIssuer`, `ValidateToken_WrongAudience`,
  `ValidateToken_WrongSigningKey`. These cover *real* invariants, so they are
  **ported** to the asymmetric service rather than dropped.

**Kept unchanged:** every RS256/ES256 test —
`TestJWTService_Provider_GenerateAndValidate_ES256`,
`TestJWTService_Provider_ExpiredToken_Rejected`,
`TestJWTService_Provider_UnknownKid_Rejected`, and everything in
`internal/signing/`.

**Added — the regression test that pins this fix:** a token with **no `kid`
header**, a *valid* HS256 signature produced with the exact former committed
`jwt_secret` value, and correct issuer/audience/expiry must be **rejected**. The
test mints the token directly with `github.com/golang-jwt/jwt/v5` (not via any
RocketVault constructor), so it keeps testing the attacker's capability even
after every symmetric code path is gone. It is the test that would have caught
this vulnerability.

Also updated: `internal/container/container_test.go` tests 9, 10, 11 and 13,
which currently assert the HS256 fallback succeeds (`…_UnknownKeySource_HS256Fallback`,
`…_ExternalPKI_HS256Fallback`) or assert the specific "JWT secret not
configured" error string (`…_MissingJWTSecret_Error`). They become assertions
that a broken `jwt.key_source` **fails startup**.

### 5. Documentation

| File | Change |
|---|---|
| `CLAUDE.md` | Authentication-services section: state that JWT validation is asymmetric-only (`kid` required) and that HS256 was removed on 2026-08-16. Config-facts section: record that `jwt_secret` and `jwt.migration_window` are no longer read by any Go code. |
| `doc/security.markdown:9,44` | Currently claims tokens "are signed with a secret (`jwt_secret`) stored in the configuration" — already stale, now actively misleading. Rewrite for RS256/ES256 via `jwt.key_source`. |
| `doc/README_ADMIN_SETUP.md:31,37` | Minimal-config sample: drop the `migration_window` line; annotate `jwt_secret` as unread (its removal from committed config is H4's). |
| `docs/testing-guide.md:16` | Sample test config: drop the `jwt_secret` line. |
| `docs/release-notes/v4.1.0-role-parity-and-authz-fix.md` | Add a breaking-change section: HS256 tokens are no longer accepted; a signing-provider failure now aborts startup. |
| `.claude/known-bugs.md` | New fixed-bug entry (next free id: **B9**) following the file's existing format. |
| Generated HTML | `doc/security.html` and `doc/README_ADMIN_SETUP.html` are rendered from the markdown above by `scripts/docsgen` (`scripts/docsgen/docs.go:31-32`); regenerate with `./scripts/docs.sh build`. |

Historical plan archives under `docs/plans/` (e.g.
`2026-05-23-azure-keyvault-parity-audit.md`, which notes "HS256 fallback still
active") and the original design doc
`docs/superpowers/specs/2026-05-22-jwt-rs256-migration-design.md` are **not**
rewritten — this repo treats shipped specs/plans as a point-in-time record.

## OIDC independence — verified, not assumed

Read `internal/services/auth/oidc_service.go`, `api/oidc.go`,
`internal/services/auth/authentication_service.go`, and
`internal/services/retry/retry_auth_service.go`. The OIDC login flow is
**unaffected**:

- OIDC's callback exchanges the authorization code with the external issuer and
  then calls `UserService.FindOrCreateExternalUser` followed by
  `AuthenticationService.IssueSessionForUser`
  (`authentication_service.go:219-222`), which delegates to the shared
  `issueSession` helper. That helper mints the access token through
  `s.jwtService.GenerateToken(...)` (`authentication_service.go:200`) — the same
  `JWTService` instance local login uses.
- `jwtService.GenerateToken` (`jwt_service.go:101-148`) **only ever** signs with
  `s.provider` (RS256/ES256) and always sets a `kid` header. There is no
  symmetric branch in it, so no OIDC-issued token loses validity.
- The ID token from the external issuer is verified by the go-oidc verifier
  against the issuer's own JWKS; it never reaches `jwtService.ValidateToken`.

Conclusion: **no OIDC file is touched by this plan, and no OIDC-issued session
is invalidated by it.** The only tokens invalidated are HS256 ones — which,
after this fix, is exactly the intended outcome.

## Explicitly out of scope

- **Rotating `jwt_secret` / removing it from `.rocketvault.yaml` and git
  history** — finding **H4**, separate plan, runs after this one.
- **`ValidateSession` trusting the JWT `role` claim** instead of re-reading the
  role from the database. It is a real defence-in-depth gap called out in H1's
  recommendation, but with HS256 gone an attacker can no longer mint a token
  with an arbitrary `role` in the first place; the remaining exposure requires
  compromise of the asymmetric private key. Fixing it means a DB read on every
  authenticated request plus a decision about role-change propagation latency —
  a design question of its own, not a line-item in this bounded fix.
- **JWKS/key-rotation behaviour** (`api/jwks.go`, `internal/signing/`) — unchanged.
- **Cross-vault authorization findings** (H2, H3) — separate plans.

## Compatibility and risk

- **Any live HS256 token is invalidated immediately** on deploy. Since RS256 is
  the only provider in use, in practice this means only forged tokens break.
  Nothing needs a grace period.
- **Startup becomes strict**: a deployment that has (silently) been running on
  the HS256 fallback because its `jwt.key_source` is misconfigured will now
  fail to start with a clear error instead of running in a forgeable state.
  This is intended, and is called out in the release notes.
- **Existing RS256 sessions survive** the deploy: `os_store` reloads the same
  key from the OS keychain, so the `kid` and signature stay valid.
- **No database, schema, API-surface, or CLI-surface change.**

## Verification gate

```bash
go build ./...
go vet ./...
go test ./internal/services/auth/... ./internal/container/... ./internal/signing/... ./api/... ./internal/middleware/...
go test ./...
grep -rn "hs256\|HS256\|migrationDeadline\|MigrationWindow" --include="*.go" internal/ api/ cmd/ bootstrap/
```

The final grep must return only `internal/crypto/crypto_operations.go`'s
`AlgorithmHS256` (the *key-operation* HMAC algorithm offered by the crypto API —
unrelated to session JWTs) and its test. No success claim without this output.
