# Architecture Review: rocketvault

**Date**: 2026-03-07
**Reviewer**: Claude Code
**Branch**: v-4.0.0
**Go version in use**: 1.25.7
**Go version declared in go.mod**: 1.24.2
**Overall test coverage**: 17.0%

---

## Executive Summary

The project has a sound architectural intent — domain-driven design, a dependency injection container,
interface-driven repositories, and a layered HTTP API. Several of these are well-executed. However,
27 concrete issues were found across five review domains. Four are Critical and must be resolved before
any production deployment. Nine are High severity and represent functional correctness risks.

---

## Review Methodology

**Approach**: Layered deep analysis — findings organised by architectural layer, each with a severity
rating (Critical / High / Medium / Low), a root-cause explanation, and a fix direction.

**Layers reviewed**:
1. Architecture — layer structure and violations
2. Go idioms and code quality
3. Security
4. Testability
5. Operational readiness

---

## Section 1 — Architecture: Layer Structure & Violations

### [Critical] Layer bypass in `api/secrets.go` — 4 handlers open a raw DB connection

**Location**: `api/secrets.go` lines 594, 670, 755, 975

**Root cause**: `listSecrets`, `getSecret`, `updateSecret`, and `generateSecret` call
`db.NewRepository(c.Logger)` and `defer database.GetDB().Close()` inside request handlers.
The first three create a connection and never use it — the work still goes through `secretService`.
`generateSecret` (line 975) bypasses the service layer entirely: it constructs a `domain.Secret`
by hand and calls `secretsRepo.Create()` directly, skipping encryption, versioning, and cache
invalidation.

**Fix direction**: Remove all `db.NewRepository` calls from API handlers. Route `generateSecret`
through `SecretService.GenerateSecret()`, which already exists and handles the full workflow.

---

### [Critical] Retry service initialised too late — auth service never gets retry

**Location**: `internal/container/service_container.go` lines 230 and 242

**Root cause**: `initializeServices()` checks `if c.retryService != nil` at line 230 to wrap the
auth service, but `c.retryService` is only assigned at line 247. At the point of the check it is
always `nil`. The auth service is the only service that silently loses its retry wrapper despite
the code implying it has one.

**Fix direction**: Move retry service initialisation before authentication service initialisation
in `initializeServices()`. Alternatively, restructure into two passes: initialise all
infrastructure (including retry) first, then wrap services.

---

### [High] `api/context.go` duplicates JWT validation

**Location**: `api/context.go` line 178

**Root cause**: `viper.GetString("jwt_secret")` is called directly to validate tokens using the
raw `golang-jwt` library, bypassing `JWTService` in the service container. Two independent token
validation paths now exist. Any future algorithm change, key rotation, or claim schema update
must be applied in two places or tokens will be accepted by one path and rejected by the other.

**Fix direction**: Remove the inline JWT parsing in `context.go`. Extract the JWT secret from the
service container's `JWTService` or call `authenticationService.ValidateSession()` directly.

---

### [Medium] `NewMiddleware` accepts a concrete type, not the interface

**Location**: `internal/middleware/middleware.go` line 65

**Root cause**: `NewMiddleware` takes `*container.ServiceContainer` (concrete) despite the
`Container` interface being defined in the same file for exactly this purpose. Any test that
exercises middleware must construct real infrastructure.

**Fix direction**: Change `NewMiddleware` to accept `Container` (the interface). Update the call
site in `api/api.go` accordingly.

---

## Section 2 — Go Idioms & Code Quality

### [High] `sql.ErrNoRows` compared with `==` instead of `errors.Is` — 14 occurrences

**Location**: `internal/repositories/` — all repository files

**Root cause**: All uses follow the pre-Go-1.13 pattern `if err == sql.ErrNoRows`. Database
drivers may wrap sentinel errors; `errors.Is` unwraps correctly. With Go 1.25.7 in use this is
a correctness risk if a wrapping driver is ever introduced.

**Fix direction**: Global search-replace `err == sql.ErrNoRows` →
`errors.Is(err, sql.ErrNoRows)` and `err != sql.ErrNoRows` → `!errors.Is(err, sql.ErrNoRows)`
across all repository files.

---

### [High] Bare `return err` propagates context-free errors

**Location**: `internal/services/keys/key_service.go:355,393`,
`internal/repositories/secret_repository.go:431,514`,
`internal/repositories/certificate_repository.go:450,517`,
`internal/repositories/user_repository.go:356`,
`internal/repositories/key_repository.go:391`

**Root cause**: Errors are returned without wrapping, so callers receive messages like
`"no such table: secrets"` with no call-site context. `errors.Is` / `errors.As` cannot
traverse unwrapped errors.

**Fix direction**: Wrap at each return site with `fmt.Errorf("operationName: %w", err)`.

---

### [High] Mixed logging styles

**Location**: `api/context.go:114,242` (stdlib `log`), `api/users.go` and `api/secrets.go`
(unstructured `Printf`), service layer (structured `logrus.WithFields`)

**Root cause**: Three logging styles coexist — stdlib `log`, `Logger.Printf`, and structured
logrus fields. Log aggregation and filtering are inconsistent.

**Fix direction**: Replace all stdlib `log` calls with the injected structured logger. Replace
`Logger.Printf(...)` calls with `Logger.WithField(...).Info(...)` to emit structured entries.

---

### [Medium] `TagService` takes raw `*sql.DB`

**Location**: `internal/services/secrets/tag_service.go:42`,
`internal/container/service_container.go:279`

**Root cause**: `NewTagService(db *sql.DB, ...)` bypasses the repository pattern that the rest
of the codebase carefully maintains, making the service impossible to unit-test without a
real database.

**Fix direction**: Introduce a `TagRepository` interface and implementation following the
existing repository pattern. Inject it into `TagService` instead of `*sql.DB`.

---

### [Medium] `context.Background()` created mid-execution in the scheduler

**Location**: `internal/services/secrets/scheduler_service.go:137`

**Root cause**: `processAllUserOperations()` creates a fresh `context.Background()`, discarding
any parent context. Rotation jobs cannot be cancelled during server shutdown and cannot inherit
deadlines or trace metadata.

**Fix direction**: Thread the server's root context into the scheduler at construction time and
use it inside `processAllUserOperations()`.

---

### [Low] `interface{}` instead of `any`

**Location**: `internal/crypto/key_crypto.go:95`, `internal/health/health.go:286`,
`internal/logging/yaml.go:18`

**Root cause**: Pre-Go-1.18 style. The project runs on Go 1.25.7 where `any` is the idiomatic
alias.

**Fix direction**: Replace `interface{}` with `any` in all non-generated files.

---

## Section 3 — Security

### [Critical] Config files containing production secrets are committed to git

**Location**: `.rocketvault.yaml`, `.rocketvault-production.yaml`,
`.rocketvault-staging.yaml` (all tracked by `git ls-files`)

**Root cause**: `master_key`, `jwt_secret`, and `bootstrap_token` are stored in plaintext in
tracked YAML files. Anyone with repository access has the master encryption key for every secret
in the database.

**Fix direction**:
1. Remove the files from git history (`git filter-repo` or `BFG`).
2. Rotate all three secrets immediately.
3. Add `*.yaml` or specific file patterns to `.gitignore`.
4. Source secrets from environment variables (`MASTER_KEY`, `JWT_SECRET`, `BOOTSTRAP_TOKEN`)
   at startup, falling back to config file only in development with a clear warning.

---

### [High] Master encryption key sourced from global viper — no key rotation support

**Location**: `common/encrypt.go:39,82`

**Root cause**: `viper.GetString("master_key")` is called on every encrypt/decrypt operation.
There is no per-secret key versioning, no key derivation per user, and no incremental rotation
path. A single key compromise exposes every stored secret simultaneously.

**Fix direction**: Introduce a `KeyProvider` interface injected into `CryptographyService`.
Store a `key_version` field alongside each encrypted secret in the DB. During rotation, re-encrypt
secrets in batches using the new key while old key remains valid for reads until migration
completes.

---

### [High] JWT secret duplicated outside the service container

**Location**: `api/context.go:178`

**Root cause**: Covered in Section 1 (architecture violation). Security implication: two
independent validation paths mean a JWT configuration change must be coordinated across both
or tokens will behave inconsistently.

**Fix direction**: Same as Section 1 fix — remove inline JWT parsing, delegate to
`JWTService` or `AuthenticationService.ValidateSession()`.

---

### [Medium] `bcrypt.DefaultCost` (10) below current OWASP recommendation

**Location**: `common/encrypt.go:21`

**Root cause**: `bcrypt.GenerateFromPassword([]byte(input), bcrypt.DefaultCost)` uses cost 10.
OWASP recommends minimum cost 12 for new applications (2024+).

**Fix direction**: Replace `bcrypt.DefaultCost` with a named constant `bcryptCost = 12`
(or higher, validated against acceptable login latency on target hardware).

---

### [Medium] TOTP secret returned in API response without audit trail

**Location**: `api/users.go:241`

**Root cause**: `TOTPSecret` is included in the `createUser` response (by design for initial
setup). There is no audit log entry recording this disclosure, and no mechanism to suppress it
if the user already has an active TOTP configuration.

**Fix direction**: Emit a structured audit log entry when a TOTP secret is disclosed. Add a
guard: if the user already has an active TOTP configured, do not return the secret in the
response and return a descriptive error instead.

---

### [Low] HSTS header set unconditionally

**Location**: `internal/middleware/middleware.go:270`

**Root cause**: `Strict-Transport-Security` is set for all requests including plain HTTP
development environments. Browsers cache HSTS and will refuse HTTP connections to the same
origin for the declared `max-age`.

**Fix direction**: Set HSTS only when the server is configured with TLS. Add a
`TLSEnabled bool` flag to middleware config and gate the header on it.

---

### [Low] JWT access token TTL hardcoded

**Location**: `internal/container/service_container.go:212`

**Root cause**: `Expiry: time.Hour` is a code constant with no configuration path. Cannot be
tuned per-environment without recompiling.

**Fix direction**: Read from `viper.GetDuration("jwt.expiry")` with a 1-hour default.

---

## Section 4 — Testability

**Overall coverage: 17.0%**

### [High] Core business logic has 0% test coverage

| Package | Coverage |
|---|---|
| `internal/services/secrets` | 0.0% |
| `internal/services/users` | 0.0% |
| `internal/services/keys` | 0.0% |
| `internal/services/certificates` | 0.0% |
| `internal/repositories` | 0.0% |
| `internal/container` | 0.0% |
| `api` (all HTTP handlers) | 0.0% |

**Fix direction**: Add unit tests for each service using the existing mock infrastructure.
Priority order: `SecretService`, `UserService`, `AuthenticationService` (session paths),
`KeyService`, `CertificateService`.

---

### [High] Auth service coverage 16.9% — critical paths untested

**Location**: `internal/services/auth/`

**Root cause**: `ValidateSession`, `RefreshAccessToken`, `RevokeSession`, `RevokeAllUserSessions`,
`JWTService` (all methods), and `PasswordService` (all methods) are at 0.0% coverage.

**Fix direction**: Add targeted tests for each uncovered method. `PasswordService` and
`JWTService` are pure functions with no external dependencies — trivial to test.

---

### [High] `NewMiddleware` concrete type blocks handler testing

**Location**: `internal/middleware/middleware.go:65`

**Root cause**: Covered in Section 1. Testability consequence: no HTTP handler can be tested
without a real `ServiceContainer`.

**Fix direction**: Same as Section 1 fix.

---

### [Medium] No `t.Parallel()` in any test

**Fix direction**: Add `t.Parallel()` to all table-driven test cases as coverage grows.
Not urgent now but will matter as the suite expands.

---

### [Medium] Mock infrastructure in `cmd/testutils` — not importable from `internal/`

**Root cause**: Internal service tests cannot import `cmd/testutils` without an import cycle.

**Fix direction**: Create `internal/testutils/` package with shared mock types. Move or
duplicate the mock definitions there. `cmd/testutils` can embed or re-export from
`internal/testutils`.

---

### [Low] Three test setup failures block root and `cmd` package tests

**Location**: `internal/db/migrations/migration_runner.go:16`

**Root cause**: `//go:embed *.sql` fails at build time because no `.sql` files exist in the
migrations directory. Any test added to `cmd/` or the root package is unreachable.

**Fix direction**: Either add a placeholder `.sql` file (e.g. `000_placeholder.sql`) or change
the embed directive to use `//go:embed *.sql` with a build tag guard. The actual schema is
managed in `internal/db/db.go`, so the migrations directory likely needs at least one real
migration file to be useful.

---

## Section 5 — Operational Readiness

### [Critical] `bootstrap.Shutdown()` never called — resources leaked on exit

**Location**: `bootstrap/bootstrap.go:151` (`Boot` function)

**Root cause**: `Boot()` creates a local `bootstrap` struct and discards it after `setup()`.
`Shutdown()`, which closes the service container and DB pool, is defined but never wired to
the OS signal handler. On `SIGTERM`, the HTTP server drains gracefully but the DB connection
pool, cache goroutine, and scheduler goroutine are abandoned.

**Fix direction**: In `Boot()`, defer `bs.Shutdown(ctx)` or wire it into the signal handler
in `server.go` after the HTTP server shuts down cleanly.

---

### [High] CI pipeline targets Go 1.20, project uses Go 1.24+

**Location**: `.github/workflows/go.yml`

**Root cause**: `go-version: '1.20'` is pinned. `go.mod` declares `go 1.24.2`; runtime is
1.25.7. CI success on 1.20 does not validate the code that ships.

**Fix direction**: Update workflow to `go-version-file: 'go.mod'` so CI always uses the
declared version.

---

### [High] No request body size limit

**Location**: API handlers — no `http.MaxBytesReader` applied anywhere

**Root cause**: Clients can stream arbitrary-size bodies. The secret import handler reads the
full body into memory before parsing — a straightforward denial-of-service vector.

**Fix direction**: Apply `r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)` in a
dedicated middleware (e.g. `RequestSizeLimitMiddleware`) applied globally, with a higher limit
for import endpoints if needed.

---

### [Medium] Rate limiter store created per-request — limits never accumulate

**Location**: `internal/middleware/middleware.go:113`

**Root cause**: `memory.NewStore()` is called inside the `http.HandlerFunc` closure, creating
a fresh store on every request. No request is ever counted more than once.

**Fix direction**: Hoist store creation to `NewMiddleware` constructor so the same store
persists for the lifetime of the server process. For multi-instance deployments, replace with
a Redis-backed store.

---

### [Medium] `docker-compose.yml` includes unused MongoDB service

**Fix direction**: Remove the `mongodb` service and `mongo_data` volume. The codebase has no
MongoDB driver.

---

### [Low] No distributed tracing

**Fix direction**: Add `X-Request-ID` header generation in middleware. Propagate via context.
Long-term: OpenTelemetry SDK with a stdout exporter as a starting point.

---

### [Low] CI has no linting, security scanning, or coverage gate

**Fix direction**: Add `golangci-lint`, `govulncheck`, and a `go test -coverprofile` step
with a minimum threshold (suggest 60% as an initial target given current state).

---

## Finding Summary

| Severity | Count |
|---|---|
| Critical | 4 |
| High | 9 |
| Medium | 8 |
| Low | 6 |
| **Total** | **27** |

### Critical (must fix before production)
1. Config files with `master_key`, `jwt_secret`, `bootstrap_token` committed to git
2. `generateSecret` and 3 other handlers bypass service layer with raw DB access
3. Retry service initialised after auth service — auth never gets retry wrapping
4. `bootstrap.Shutdown()` never called — DB pool and goroutines leaked on exit

### High (functional correctness risks)
5. JWT validation duplicated in `api/context.go`, bypassing `JWTService`
6. `sql.ErrNoRows` compared with `==` instead of `errors.Is` (14 occurrences)
7. Bare `return err` without wrapping across repositories and key service
8. Mixed logging styles (stdlib, Printf, structured logrus)
9. Master key sourced from global viper — no rotation support
10. `bcrypt.DefaultCost` below OWASP recommendation
11. 0% test coverage on all service, repository, and API packages
12. Auth service critical paths (ValidateSession, RefreshToken, etc.) untested
13. CI Go version mismatch (1.20 vs 1.24.2)

### Medium
14. `NewMiddleware` takes concrete `*ServiceContainer` instead of `Container` interface
15. `TagService` takes raw `*sql.DB` — bypasses repository pattern
16. Scheduler creates `context.Background()` mid-execution
17. TOTP secret disclosed without audit log entry
18. Rate limiter store created per-request — never accumulates counts
19. Mock infrastructure not importable from `internal/` packages
20. Unused MongoDB service in docker-compose
21. HSTS set unconditionally (breaks HTTP-only dev)

### Low
22. `interface{}` used instead of `any`
23. JWT TTL hardcoded (not configurable)
24. Migration embed directive fails (no `.sql` files) — blocks root/cmd test packages
25. No `t.Parallel()` in any test
26. No distributed tracing / request ID propagation
27. CI has no linting, security scanning, or coverage gate
