# Remove HS256 JWT Fallback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete the legacy HS256 (symmetric HMAC) JWT verification path so that `jwtService.ValidateToken` accepts only tokens carrying a `kid` header resolvable to the configured asymmetric signing provider — closing pentest finding H1 (JWT forgery with the repo-committed `jwt_secret` → full admin takeover).

**Architecture:** `internal/services/auth/jwt_service.go` currently holds two implementations of the `JWTService` interface: `jwtService` (asymmetric, RS256/ES256, via `signing.SigningKeyProvider`) and `legacyJWTService` (HS256, keyed on `JWTConfig.SecretKey`). `jwtService.ValidateToken` also carries an HS256 fallback for `kid`-less tokens, gated by a `migrationDeadline` that is recomputed as `time.Now() + jwt.migration_window` on every process boot and therefore never closes. This plan removes the fallback, the whole `legacyJWTService`, and the `SecretKey`/`MigrationWindow` config fields, and makes the asymmetric provider mandatory in `internal/container/service_container.go` (a provider failure now aborts startup instead of silently degrading to HS256). Task order is chosen so every task compiles and tests green on its own: container wiring first (removes the only production caller of the symmetric service), then the validation path, then the dead symmetric code, then docs, then the known-bugs entry.

**Tech Stack:** Go 1.24.2, `github.com/golang-jwt/jwt/v5`, `github.com/spf13/viper`, `github.com/sirupsen/logrus`, testify (`assert`/`require`), `rocketvault/internal/signing` (`os_store` / `self_pki` / `external_pki` providers), `scripts/docs.sh` (markdown → styled HTML docs).

**Spec:** `docs/superpowers/specs/2026-08-16-remove-hs256-jwt-fallback-design.md` — §"The vulnerability", §"Why removal (not repair)", §"Scope of the change" (1-5), §"OIDC independence — verified, not assumed", §"Explicitly out of scope", §"Verification gate".

## Global Constraints

- **Do not edit `.rocketvault.yaml`.** Removing/rotating the committed `jwt_secret` and deleting `jwt.migration_window` from the shipped config is finding **H4**'s separate plan, which runs after this one. After this plan both keys are simply unread by any Go code.
- **Do not touch `internal/services/auth/oidc_service.go`, `api/oidc.go`, or any other OIDC file.** OIDC issues sessions through `AuthenticationService.IssueSessionForUser` → `jwtService.GenerateToken`, which is asymmetric-only and unchanged (verified in the spec).
- **Do not weaken or delete tests for the RS256/ES256 path**, nor anything under `internal/signing/`.
- `internal/crypto/crypto_operations.go`'s `AlgorithmHS256` is the **key-operation** HMAC algorithm exposed by the crypto API. It is unrelated to session JWTs — leave it and its tests alone.
- Comments follow the project convention: short full sentences, ending with a punctuation mark. No emojis.
- Every task ends with `go build ./...` passing before its commit.
- Commits must be GPG-signed (repo convention); use the repo's existing `git commit` configuration, no `--no-gpg-sign`.

---

## Files Created or Modified

| File | Action | Purpose |
|---|---|---|
| `internal/container/service_container.go` | Modify | Make the asymmetric signing provider mandatory; drop `SecretKey`/`MigrationWindow` from the `JWTConfig` literal and the HS256 fallback branch (Task 1) |
| `internal/container/container_test.go` | Modify | Replace the three HS256-fallback tests with startup-failure assertions; drop `jwt_secret` seeding (Task 1) |
| `internal/services/auth/jwt_service.go` | Modify | Reject `kid`-less tokens (Task 2); delete `legacyJWTService`, `NewJWTService`, `JWTConfig.SecretKey`, `JWTConfig.MigrationWindow` (Task 3) |
| `internal/services/auth/jwt_service_provider_test.go` | Modify | Add the forged-token regression test (Task 2); delete the two fallback tests and port the legacy edge-case tests to the asymmetric service (Task 3) |
| `internal/services/auth/jwt_service_test.go` | Delete | Both tests construct `NewJWTService`; coverage duplicated by the provider tests (Task 3) |
| `internal/services/auth/auth_edge_cases_test.go` | Modify | Delete the "legacyJWTService" block (Task 3) |
| `bootstrap/bootstrap_test.go` | Modify | Drop the now-meaningless `jwt_secret` viper seed (Task 3) |
| `CLAUDE.md` | Modify | Auth-services + config-facts notes (Task 4) |
| `doc/security.markdown` | Modify | Replace the "signed with `jwt_secret`" claim with asymmetric signing (Task 4) |
| `doc/README_ADMIN_SETUP.md` | Modify | Drop `migration_window` from the sample config; annotate `jwt_secret` as unread (Task 4) |
| `docs/testing-guide.md` | Modify | Drop `jwt_secret` from the sample test config (Task 4) |
| `docs/release-notes/v4.1.0-role-parity-and-authz-fix.md` | Modify | Breaking-change section for HS256 removal (Task 4) |
| `doc/security.html`, `doc/README_ADMIN_SETUP.html` | Regenerate | Rendered by `./scripts/docs.sh build` (Task 4) |
| `.claude/known-bugs.md` | Modify | New fixed-bug entry **B9** (Task 5) |

---

## Task 1: Make the asymmetric signing provider mandatory in the container

Removes the only production code path that constructs the symmetric JWT service, and stops the container from reading `jwt_secret` / `jwt.migration_window`. `NewJWTService` still exists after this task (deleted in Task 3), so everything compiles.

**Files:**
- Modify: `internal/container/service_container.go:336-370`
- Test: `internal/container/container_test.go` (tests 9, 10, 11, 13 — lines 377-520)

**Interfaces:**
- Consumes: `signing.NewProvider(v *viper.Viper, deps signing.ProviderDeps) (signing.SigningKeyProvider, error)`; `authServices.NewJWTServiceWithProvider(config authServices.JWTConfig, provider signing.SigningKeyProvider) authServices.JWTService`.
- Produces: after this task `ServiceContainer.signingProvider` is never nil on a successfully constructed container, and `NewServiceContainer` returns an error whose message contains `"JWT signing provider initialisation failed"` when `signing.NewProvider` fails.

- [ ] **Step 1: Rewrite the three HS256-fallback container tests as startup-failure tests**

In `internal/container/container_test.go`, replace the whole block from the `// Test 10 …` comment header down to the end of `TestNewServiceContainer_MissingJWTSecret_Error` (currently lines 408-459) with:

```go
// ---------------------------------------------------------------------------
// Test 10 — NewServiceContainer with an unknown jwt.key_source
// ---------------------------------------------------------------------------

// TestNewServiceContainer_UnknownKeySource_Error verifies that an unusable
// signing provider now aborts container initialisation. Before the HS256
// fallback was removed (2026-08-16) this silently degraded to symmetric
// signing whenever jwt_secret happened to be set, which made forged
// kid-less tokens verifiable with a repo-committed secret.
func TestNewServiceContainer_UnknownKeySource_Error(t *testing.T) {
	v := viper.New()
	v.Set("jwt.key_source", "unknown_provider") // signing provider fails

	cfg := Config{
		Database:    openSQLite(t),
		Logger:      newTestLogger(),
		CacheConfig: cacheConfigWithSecretsDisabled(t),
		Viper:       v,
	}

	_, err := NewServiceContainer(cfg)
	require.Error(t, err, "an unusable signing provider must abort startup")
	assert.Contains(t, err.Error(), "JWT signing provider initialisation failed")
	assert.Contains(t, err.Error(), "unknown jwt.key_source")
}
```

Then replace `TestNewServiceContainer_ExternalPKI_HS256Fallback` (currently lines 489-520, including its comment header) with:

```go
// ---------------------------------------------------------------------------
// Test 11 — NewServiceContainer with external_pki and no key material
// ---------------------------------------------------------------------------

// TestNewServiceContainer_ExternalPKI_NoFile_Error exercises the code path
// where the signing provider is configured as "external_pki" with no key file
// and no env var. There is no symmetric fallback any more, so this must fail
// startup rather than quietly issuing HS256-verifiable sessions.
func TestNewServiceContainer_ExternalPKI_NoFile_Error(t *testing.T) {
	// Ensure env var is absent so external_pki returns an error.
	t.Setenv("ROCKETVAULT_JWT_SIGNING_KEY", "")

	v := viper.New()
	v.Set("jwt.key_source", "external_pki")
	v.Set("jwt.signing_key_file", "") // no file path — provider will fail

	cfg := Config{
		Database:    openSQLite(t),
		Logger:      newTestLogger(),
		CacheConfig: cacheConfigWithSecretsDisabled(t),
		Viper:       v,
	}

	_, err := NewServiceContainer(cfg)
	require.Error(t, err, "external_pki with no key material must abort startup")
	assert.Contains(t, err.Error(), "JWT signing provider initialisation failed")
}
```

Finally, in `TestNewServiceContainer_NilViper` (currently lines 380-386), delete the global-viper `jwt_secret` seeding so the test proves the default `os_store` provider carries the container on its own. Replace the comment plus the `viper.Set`/`t.Cleanup` block at the top of the function body with nothing, so the function starts:

```go
func TestNewServiceContainer_NilViper(t *testing.T) {
	// No jwt_secret is seeded: with the HS256 fallback gone, the default
	// jwt.key_source ("os_store") must carry the container on its own.
	cfg := Config{
		Database:    openSQLite(t),
		Logger:      newTestLogger(),
		CacheConfig: cacheConfigWithSecretsDisabled(t),
		Viper:       nil, // trigger fallback to global viper
	}
```

- [ ] **Step 2: Run the container tests to verify they fail**

Run: `go test ./internal/container/ -run 'TestNewServiceContainer_(UnknownKeySource_Error|ExternalPKI_NoFile_Error|NilViper)' -v`
Expected: FAIL — `TestNewServiceContainer_UnknownKeySource_Error` and `TestNewServiceContainer_ExternalPKI_NoFile_Error` report `Error "failed to initialize services: JWT secret not configured and asymmetric provider unavailable" does not contain "JWT signing provider initialisation failed"`. (`TestNewServiceContainer_NilViper` should already pass.)

- [ ] **Step 3: Make the provider mandatory in the container**

In `internal/container/service_container.go`, replace lines 336-370 (from the `// Initialize JWT signing provider.` comment through the `c.jwtService = authServices.NewJWTService(jwtConfig)` block) with:

```go
	// Initialize JWT signing provider. Asymmetric signing is mandatory: there
	// is no symmetric fallback, so a provider failure must abort startup.
	signingDeps := signing.ProviderDeps{
		CryptoService: c.cryptoService,
		KeyRepository: c.keyRepository,
	}
	provider, err := signing.NewProvider(viperCfg, signingDeps)
	if err != nil {
		return fmt.Errorf("JWT signing provider initialisation failed: %w", err)
	}
	c.signingProvider = provider

	// Initialize JWT service with configuration.
	jwtExpiry := viperCfg.GetDuration("jwt.expiry")
	if jwtExpiry == 0 {
		jwtExpiry = time.Hour // Default to 1 hour.
	}
	jwtConfig := authServices.JWTConfig{
		Issuer:   viperCfg.GetString("oauth2.issuer"),
		Audience: "PASSWORD_MANAGER",
		Expiry:   jwtExpiry,
		Logger:   c.logger.Logger,
	}

	c.jwtService = authServices.NewJWTServiceWithProvider(jwtConfig, provider)
```

- [ ] **Step 4: Run the container tests to verify they pass**

Run: `go build ./... && go test ./internal/container/ -v`
Expected: PASS — all container tests, including the three rewritten ones.

- [ ] **Step 5: Commit**

```bash
git add internal/container/service_container.go internal/container/container_test.go
git commit -m "fix(auth): require an asymmetric JWT signing provider at startup

The container previously downgraded to the legacy HS256 JWT service
whenever signing.NewProvider failed, keyed on the static jwt_secret
from config. That secret is committed to the repo, so the downgrade
path let anyone who can read the repo mint tokens. There is no
population of legacy HS256 tokens to migrate on this branch, so a
provider failure is now a hard startup error instead.

Also stops reading jwt_secret and jwt.migration_window from viper:
nothing in the container consumes them any more."
```

---

## Task 2: Reject `kid`-less tokens in `jwtService.ValidateToken`

This is the security fix proper, pinned by a regression test that reproduces the pentest exploit exactly.

**Files:**
- Modify: `internal/services/auth/jwt_service.go:31-41` (struct fields), `:65-82` (`NewJWTServiceWithProvider`), `:150-166` (`ValidateToken`), `:197-222` (`validateHS256Fallback`)
- Test: `internal/services/auth/jwt_service_provider_test.go`

**Interfaces:**
- Consumes: `auth.NewJWTServiceWithProvider(config auth.JWTConfig, provider signing.SigningKeyProvider) auth.JWTService`; the test helpers `newStaticProvider(t *testing.T) *staticProvider` and `newProviderJWT(t *testing.T, extraCfg ...func(*auth.JWTConfig)) auth.JWTService` already in `jwt_service_provider_test.go:25-55`.
- Produces: `jwtService.ValidateToken` returns `(nil, error)` whose message contains `"missing kid header"` for any token without a `kid` header. Task 3 relies on `hs256SecretKey`/`migrationDeadline` no longer existing on the `jwtService` struct after this task.

- [ ] **Step 1: Write the failing regression test**

Add the `jwt` import to `internal/services/auth/jwt_service_provider_test.go` — the import block becomes:

```go
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/auth"
	"rocketvault/internal/signing"
)
```

Then append to the same file:

```go
// leakedJWTSecret is the exact HS256 secret that was committed to
// .rocketvault.yaml and is therefore public in git history. The forgery test
// below signs with it deliberately: the point is that even a *correct* HMAC
// signature over well-formed claims must not authenticate anybody.
const leakedJWTSecret = "***SECRET-REMOVED-2026-08-17***"

// forgedHS256Token mints a token the way the 2026-08-16 pentest did: no kid
// header, HS256 signature, correct issuer/audience, and a jti that a normal
// low-privilege login would have produced. It is built with golang-jwt
// directly, not through any RocketVault constructor, so it keeps modelling the
// attacker's capability after every symmetric code path is gone.
func forgedHS256Token(t *testing.T, secret string) string {
	t.Helper()
	now := time.Now()
	claims := auth.JWTClaims{
		UserID:   uuid.New(),
		Username: "vaultuser1",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "rocketvault",
			Subject:   uuid.New().String(),
			Audience:  jwt.ClaimStrings{"PASSWORD_MANAGER"},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	require.NoError(t, err)
	return signed
}

// TestJWTService_Provider_KidlessHS256Token_Rejected is the regression test for
// pentest finding H1. The service is configured the way production was — with
// the leaked secret and an open migration window — and must still reject the
// forged token, because the HS256 verification path no longer exists.
func TestJWTService_Provider_KidlessHS256Token_Rejected(t *testing.T) {
	svc := newProviderJWT(t, func(c *auth.JWTConfig) {
		c.SecretKey = leakedJWTSecret
		c.MigrationWindow = time.Hour
	})

	claims, err := svc.ValidateToken(forgedHS256Token(t, leakedJWTSecret))

	require.Error(t, err, "a token with no kid header must never be accepted")
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "missing kid header")
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/services/auth/ -run TestJWTService_Provider_KidlessHS256Token_Rejected -v`
Expected: FAIL — `Error "" is not nil` / "a token with no kid header must never be accepted". The forged admin token is currently **accepted**, which is the live vulnerability.

- [ ] **Step 3: Remove the HS256 fallback from the validation path**

In `internal/services/auth/jwt_service.go`, make three edits.

Replace the `jwtService` struct (lines 31-41) with:

```go
// jwtService uses an asymmetric SigningKeyProvider for signing.
// There is no symmetric verification path: every accepted token must carry a
// kid that resolves to one of the provider's public keys.
type jwtService struct {
	provider signing.SigningKeyProvider
	issuer   string
	audience string
	expiry   time.Duration
	logger   *logrus.Logger
}
```

Replace `NewJWTServiceWithProvider` (lines 62-82) with:

```go
// NewJWTServiceWithProvider creates a JWT service backed by an asymmetric signing provider.
func NewJWTServiceWithProvider(config JWTConfig, provider signing.SigningKeyProvider) JWTService {
	logger := config.Logger
	if logger == nil {
		logger = logrus.StandardLogger()
	}
	return &jwtService{
		provider: provider,
		issuer:   config.Issuer,
		audience: config.Audience,
		expiry:   config.Expiry,
		logger:   logger,
	}
}
```

Replace `ValidateToken` (lines 150-166) and delete `validateHS256Fallback` entirely (lines 197-222), so that region reads:

```go
// ValidateToken verifies a JWT. Dispatches by kid to the correct asymmetric key.
// A token without a kid header is rejected: the legacy HS256 fallback was
// removed on 2026-08-16 because its verification key was a static, publicly
// readable config value, which made admin tokens forgeable.
func (s *jwtService) ValidateToken(tokenString string) (*JWTClaims, error) {
	// Peek at the kid header without full validation.
	unverified, _, err := jwt.NewParser().ParseUnverified(tokenString, &JWTClaims{})
	if err != nil {
		return nil, fmt.Errorf("invalid JWT token: %w", err)
	}

	kid, _ := unverified.Header["kid"].(string)

	if kid == "" {
		s.logger.WithField("alg", unverified.Header["alg"]).
			Warn("Rejected JWT with no kid header — asymmetric signing is mandatory")
		return nil, fmt.Errorf("invalid JWT token: missing kid header")
	}

	return s.validateAsymmetric(tokenString, kid)
}
```

Leave `validateAsymmetric`, `validateCommonClaims`, `GenerateToken`, and `ParseToken` untouched.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go build ./... && go test ./internal/services/auth/ -run TestJWTService_Provider -v`
Expected: PASS for `TestJWTService_Provider_KidlessHS256Token_Rejected`, `TestJWTService_Provider_GenerateAndValidate_ES256`, `TestJWTService_Provider_ExpiredToken_Rejected`, and `TestJWTService_Provider_UnknownKid_Rejected`. FAIL is still expected for `TestJWTService_Provider_HS256Fallback_ActiveWindow` (it asserts the forged-format token is accepted) — Task 3 deletes it. Do not "fix" that test by re-adding the fallback.

- [ ] **Step 5: Commit**

```bash
git add internal/services/auth/jwt_service.go internal/services/auth/jwt_service_provider_test.go
git commit -m "fix(auth): reject JWTs with no kid header (removes HS256 fallback)

ValidateToken fell back to HMAC-SHA256 verification for any token
without a kid header while a migration window was open. The window's
deadline was computed as now+jwt.migration_window at service
construction, so it restarted on every process boot and never closed,
and its verification key was jwt_secret — a static value committed to
the repo. A token with no kid, role: admin and a real session jti,
signed with that secret, was accepted by admin-only endpoints.

Asymmetric verification (RS256/ES256 via the signing provider) is now
the only path. Adds the regression test that reproduces the exploit."
```

---

## Task 3: Delete `legacyJWTService`, `NewJWTService`, and the symmetric config fields

Nothing calls the symmetric service any more (Task 1 removed the production caller, Task 2 removed the fallback). `legacyJWTService.GenerateToken` is the only code in the repo that can *mint* an HS256 token, so it goes too — otherwise the forgery primitive stays one call away.

**Files:**
- Modify: `internal/services/auth/jwt_service.go` (`JWTConfig` fields, `legacyJWTService` type + constructor + three methods)
- Modify: `internal/services/auth/jwt_service_provider_test.go` (drop the two fallback tests; drop the now-removed config fields from the Task 2 test; port the legacy edge-case tests)
- Delete: `internal/services/auth/jwt_service_test.go`
- Modify: `internal/services/auth/auth_edge_cases_test.go:122-225` (delete the legacyJWTService block)
- Modify: `bootstrap/bootstrap_test.go:293`

**Interfaces:**
- Consumes: `auth.JWTService` interface (unchanged: `GenerateToken`, `ValidateToken`, `ParseToken`); `auth.NewJWTServiceWithProvider`; test helpers `newStaticProvider`, `newProviderJWT`, and `staticProvider.kid` (settable field, see `jwt_service_provider_test.go:20-23`).
- Produces: `auth.JWTConfig` is reduced to `{Issuer, Audience string; Expiry time.Duration; Logger *logrus.Logger}`. `auth.NewJWTService` no longer exists.

- [ ] **Step 1: Delete the tests that exercise the symmetric service**

In `internal/services/auth/jwt_service_provider_test.go`, delete `TestJWTService_Provider_HS256Fallback_ActiveWindow` (lines 90-111) and `TestJWTService_Provider_HS256Fallback_ExpiredWindow_Rejected` (lines 113-133) in full.

In the Task 2 test `TestJWTService_Provider_KidlessHS256Token_Rejected`, drop the config closure that sets the fields being removed, so the service construction becomes:

```go
func TestJWTService_Provider_KidlessHS256Token_Rejected(t *testing.T) {
	svc := newProviderJWT(t)

	claims, err := svc.ValidateToken(forgedHS256Token(t, leakedJWTSecret))

	require.Error(t, err, "a token with no kid header must never be accepted")
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "missing kid header")
}
```

Delete the file `internal/services/auth/jwt_service_test.go` — both of its tests construct `NewJWTService`, and their behaviour is already covered for the asymmetric path by `TestJWTService_Provider_ExpiredToken_Rejected` and `TestJWTService_Provider_GenerateAndValidate_ES256`:

```bash
git rm internal/services/auth/jwt_service_test.go
```

In `internal/services/auth/auth_edge_cases_test.go`, delete the whole block from the `// ---` header comment `// legacyJWTService (NewJWTService — HS256 path)` through the end of `TestLegacyJWTService_ValidateToken_WrongSigningKey` (lines 122-225), i.e. everything up to but not including the `// RevokeAllUserSessions` header comment.

- [ ] **Step 2: Port the deleted edge-case coverage onto the asymmetric service**

Those four legacy tests covered real invariants (issuer, audience, signing key, `ParseToken`). Append their asymmetric equivalents to `internal/services/auth/jwt_service_provider_test.go`:

```go
func TestJWTService_Provider_ParseToken(t *testing.T) {
	svc := newProviderJWT(t)

	userID := uuid.New()
	token, err := svc.GenerateToken(userID, "alice", "user", uuid.New())
	require.NoError(t, err)

	// ParseToken must succeed without signature verification.
	claims, err := svc.ParseToken(token)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, "alice", claims.Username)
}

func TestJWTService_Provider_ParseToken_MalformedToken(t *testing.T) {
	svc := newProviderJWT(t)

	_, err := svc.ParseToken("not.a.valid.jwt.token")
	assert.Error(t, err)
}

func TestJWTService_Provider_ValidateToken_WrongIssuer(t *testing.T) {
	// Both services share one provider, so the kid resolves; only the issuer differs.
	provider := newStaticProvider(t)
	signer := auth.NewJWTServiceWithProvider(auth.JWTConfig{
		Issuer:   "other-issuer",
		Audience: "PASSWORD_MANAGER",
		Expiry:   time.Hour,
	}, provider)
	validator := auth.NewJWTServiceWithProvider(auth.JWTConfig{
		Issuer:   "rocketvault",
		Audience: "PASSWORD_MANAGER",
		Expiry:   time.Hour,
	}, provider)

	token, err := signer.GenerateToken(uuid.New(), "alice", "user", uuid.New())
	require.NoError(t, err)

	_, err = validator.ValidateToken(token)
	assert.Error(t, err)
}

func TestJWTService_Provider_ValidateToken_WrongAudience(t *testing.T) {
	provider := newStaticProvider(t)
	signer := auth.NewJWTServiceWithProvider(auth.JWTConfig{
		Issuer:   "rocketvault",
		Audience: "OTHER_AUDIENCE",
		Expiry:   time.Hour,
	}, provider)
	validator := auth.NewJWTServiceWithProvider(auth.JWTConfig{
		Issuer:   "rocketvault",
		Audience: "PASSWORD_MANAGER",
		Expiry:   time.Hour,
	}, provider)

	token, err := signer.GenerateToken(uuid.New(), "alice", "user", uuid.New())
	require.NoError(t, err)

	_, err = validator.ValidateToken(token)
	assert.Error(t, err)
}

func TestJWTService_Provider_ValidateToken_WrongSigningKey(t *testing.T) {
	// Two providers with the same kid but different key material: the validator
	// finds a key for the kid, and the signature check is what must fail.
	signerProvider := newStaticProvider(t)
	validatorProvider := newStaticProvider(t)
	require.Equal(t, signerProvider.KeyID(), validatorProvider.KeyID())

	cfg := auth.JWTConfig{
		Issuer:   "rocketvault",
		Audience: "PASSWORD_MANAGER",
		Expiry:   time.Hour,
	}
	signer := auth.NewJWTServiceWithProvider(cfg, signerProvider)
	validator := auth.NewJWTServiceWithProvider(cfg, validatorProvider)

	token, err := signer.GenerateToken(uuid.New(), "alice", "user", uuid.New())
	require.NoError(t, err)

	_, err = validator.ValidateToken(token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JWT token")
}
```

- [ ] **Step 3: Run the ported tests and record them green**

These are regression pins for behaviour the asymmetric service already has, not new behaviour, so they must pass *before* the deletion — that is what makes them meaningful evidence that Step 4 removed only dead code.

Run: `go test ./internal/services/auth/ -run TestJWTService_Provider -v`
Expected: PASS for all `TestJWTService_Provider_*` tests, including the four ported ones. Keep this output; Step 5 must reproduce it identically after the deletion.

- [ ] **Step 4: Delete the symmetric implementation and its config fields**

In `internal/services/auth/jwt_service.go`:

Delete the `legacyJWTService` struct (lines 43-50) and the `NewJWTService` constructor (lines 84-98). Delete the entire `// --- legacyJWTService (HS256 only) ---` section at the bottom of the file (lines 250-332): the `GenerateToken`, `ValidateToken`, and `ParseToken` methods on `*legacyJWTService`.

Replace `JWTConfig` (lines 52-60) with:

```go
// JWTConfig holds configuration for JWT service.
type JWTConfig struct {
	Issuer   string
	Audience string
	Expiry   time.Duration
	Logger   *logrus.Logger
}
```

In `bootstrap/bootstrap_test.go`, delete line 293 — `viper.Set("jwt_secret", "test-super-secret-jwt-key-at-least-32-chars")` — from `TestBoot_FullStack`. Nothing reads that key any more; `jwt.key_source` defaults to `os_store`, which never fails.

If deleting the legacy test block in Step 1 left any import unused in `auth_edge_cases_test.go`, the build in Step 5 will say so — drop the offending import rather than re-adding a use for it.

- [ ] **Step 5: Run the full test suite to verify it passes**

Run: `go build ./... && go vet ./... && go test ./internal/services/auth/... ./internal/container/... ./internal/signing/... ./bootstrap/... ./api/... ./internal/middleware/...`
Expected: PASS everywhere. Then confirm the symmetric path is gone:

Run: `grep -rn "hs256\|HS256\|migrationDeadline\|MigrationWindow\|legacyJWTService" --include="*.go" internal/ api/ cmd/ bootstrap/ app/ config/`
Expected: only `internal/crypto/crypto_operations.go` (`AlgorithmHS256`) and `internal/crypto/crypto_operations_test.go`, plus the `leakedJWTSecret`/`forgedHS256Token` regression-test helpers in `internal/services/auth/jwt_service_provider_test.go`.

- [ ] **Step 6: Commit**

```bash
git add internal/services/auth/jwt_service.go internal/services/auth/jwt_service_provider_test.go internal/services/auth/auth_edge_cases_test.go internal/services/auth/jwt_service_test.go bootstrap/bootstrap_test.go
git commit -m "refactor(auth): delete the legacy HS256 JWT service

legacyJWTService/NewJWTService had no callers left after the container
and ValidateToken changes, and its GenerateToken was the only code in
the repo that could mint an HS256 token — the exact primitive the
2026-08-16 pentest used. JWTConfig loses SecretKey and MigrationWindow.

Legacy edge-case coverage (ParseToken, wrong issuer, wrong audience,
wrong signing key) is ported onto the asymmetric service rather than
dropped."
```

---

## Task 4: Update the documentation that describes HS256 as active

**Files:**
- Modify: `CLAUDE.md:172-177` (auth services) and `CLAUDE.md:422-428` (config facts)
- Modify: `doc/security.markdown:9,44`
- Modify: `doc/README_ADMIN_SETUP.md:29-37`
- Modify: `docs/testing-guide.md:14-16`
- Modify: `docs/release-notes/v4.1.0-role-parity-and-authz-fix.md` (append a section)
- Regenerate: `doc/security.html`, `doc/README_ADMIN_SETUP.html`

**Interfaces:**
- Consumes: nothing from earlier tasks at compile time; the wording below must match the behaviour implemented in Tasks 1-3 (asymmetric-only validation, mandatory provider, `jwt_secret`/`jwt.migration_window` unread).
- Produces: the doc state that Task 5's known-bugs entry and H4's follow-up plan both reference.

- [ ] **Step 1: Update `CLAUDE.md`**

In the "Authentication Services" list, replace the `JWTService` bullet (line 175):

```markdown
- **JWTService**: JWT token creation and validation only. Asymmetric-only since 2026-08-16: tokens are signed RS256/ES256 through `internal/signing`'s `SigningKeyProvider`, always carry a `kid` header, and `ValidateToken` rejects any token without one. The legacy HS256 "migration window" fallback and the `legacyJWTService` implementation were deleted (pentest finding H1 — the fallback's HMAC key was the repo-committed `jwt_secret`, and its deadline was recomputed on every boot so the window never closed). A signing-provider failure now aborts startup instead of degrading to HS256 — see `docs/superpowers/specs/2026-08-16-remove-hs256-jwt-fallback-design.md`.
```

In the same section, append one sentence to the end of the `OIDCService` bullet (line 177), after "...no separate OIDC token-issuance path to drift out of sync.":

```markdown
That shared path is asymmetric-only, so the 2026-08-16 HS256 removal changed nothing about OIDC login.
```

In "Config facts (2026-03-08)", add one bullet after the `jwt.expiry` bullet (line 425):

```markdown
- `jwt_secret` and `jwt.migration_window` are **no longer read by any Go code** (HS256 removal, 2026-08-16). They still appear in `.rocketvault.yaml`; removing and rotating them is tracked as pentest finding H4. `jwt.key_source` (default `os_store`) is now mandatory — if its provider cannot be constructed, startup fails rather than falling back.
```

- [ ] **Step 2: Update `doc/security.markdown`**

Replace the JWT Authentication bullet (line 9):

```markdown
- **JWT Authentication**: Uses `github.com/golang-jwt/jwt/v5` to issue short-lived JSON Web Tokens for user sessions. Tokens are signed asymmetrically (RS256/ES256) with a private key supplied by the configured `jwt.key_source` provider — `os_store` (OS keychain, the default), `self_pki`, or `external_pki`. Every token carries a `kid` header, and validation rejects any token without one; there is no symmetric (HS256) verification path.
```

Replace the Secure Configuration bullet (line 44):

```markdown
- **Secure Configuration**: Store `master_key` in a secure vault (e.g., HashiCorp Vault) or restricted environment variables. The JWT signing key is held by the `jwt.key_source` provider, not in configuration.
```

- [ ] **Step 3: Update `doc/README_ADMIN_SETUP.md`**

In the "Minimal working configuration" YAML block, delete the `migration_window: "24h"` line and annotate the secret, so the top of the block reads:

```yaml
master_key: "***SECRET-REMOVED-2026-08-17***"
jwt_secret: "***SECRET-REMOVED-2026-08-17***"  # unread since 2026-08-16; removal tracked separately
jwt:
  key_source: "os_store"
  key_cn: "rocketvault"
  expiry: "1h"
  rotation_overlap: "1h"
bootstrap_token: "***SECRET-REMOVED-2026-08-17***"
```

- [ ] **Step 4: Update `docs/testing-guide.md`**

In the "Test Configuration" YAML block, delete the line `jwt_secret: "test-jwt-secret-for-testing"`, so the block starts:

```yaml
master_key: "***SECRET-REMOVED-2026-08-17***"
bootstrap_token: "test-bootstrap-token-12345"
```

- [ ] **Step 5: Add the release-notes section**

Append to `docs/release-notes/v4.1.0-role-parity-and-authz-fix.md`:

```markdown
## Breaking: HS256 JWTs are no longer accepted

The legacy HS256 verification path is removed. `ValidateToken` accepts only
tokens carrying a `kid` header that resolves to a public key published by the
configured `jwt.key_source` provider (RS256/ES256). `jwt_secret` and
`jwt.migration_window` are no longer read by any code — leaving them in
`.rocketvault.yaml` is harmless but has no effect.

Why: the fallback's HMAC key was `jwt_secret`, a static value committed to the
repository, and its deadline was recomputed as `now + jwt.migration_window` at
service construction, so the "24h window" restarted on every process boot and
never closed. Anyone who could read the repository could mint an admin token.
Rotate `jwt_secret` anyway if you ever deployed with the shipped value.

Also breaking: a signing-provider failure now aborts startup with
`JWT signing provider initialisation failed: …` instead of silently degrading
to HS256. In practice the default `os_store` provider cannot fail — it
auto-generates a key when the keychain is empty — so this only affects
deployments with a misconfigured `jwt.key_source`, `external_pki` without key
material, or `self_pki` without its dependencies.

Sessions signed by the existing asymmetric key survive the upgrade unchanged.

Full design: `docs/superpowers/specs/2026-08-16-remove-hs256-jwt-fallback-design.md`.
```

- [ ] **Step 6: Regenerate the HTML docs and verify**

Run: `./scripts/docs.sh build`
Expected: success, with `doc/security.html` and `doc/README_ADMIN_SETUP.html` rewritten.

Run: `grep -rn "migration_window\|HS256" doc/security.html doc/README_ADMIN_SETUP.html docs/testing-guide.md CLAUDE.md | grep -v "no longer\|removed\|removal\|rejects"`
Expected: no output.

- [ ] **Step 7: Commit**

```bash
git add CLAUDE.md doc/security.markdown doc/security.html doc/README_ADMIN_SETUP.md doc/README_ADMIN_SETUP.html docs/testing-guide.md docs/release-notes/v4.1.0-role-parity-and-authz-fix.md
git commit -m "docs: record that JWT validation is asymmetric-only

doc/security.markdown still claimed tokens are signed with jwt_secret,
which was already stale under RS256 and is now actively wrong. CLAUDE.md
gains the asymmetric-only note plus a config fact that jwt_secret and
jwt.migration_window are unread. Sample configs drop migration_window
and the test jwt_secret, and the v4.1.0 notes get the breaking-change
entry. Regenerated the two affected HTML docs via scripts/docs.sh."
```

---

## Task 5: Record the fix in `.claude/known-bugs.md`

`.claude/known-bugs.md` is the living source of truth for bug status in this repo (CLAUDE.md says so explicitly). A confirmed, exploited High-severity finding belongs there with its root cause, not only in the pentest report.

**Files:**
- Modify: `.claude/known-bugs.md` (insert after the B8 entry, before the `## Deferred Refactors` header)

**Interfaces:**
- Consumes: the file's existing fixed-entry format — `### B<N> — <title>`, then `**Status**`, `**Severity**`, `**File**`, then `**Root cause**`/`**What was fixed**` prose (see B2, B4, B8).
- Produces: entry id **B9**, referenced by H4's follow-up plan.

- [ ] **Step 1: Insert the B9 entry**

In `.claude/known-bugs.md`, immediately after the B8 entry's closing `---` and before the `## Deferred Refactors` header, insert:

```markdown
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
```

- [ ] **Step 2: Verify the file still renders as expected**

Run: `grep -n "^### B\|^## " .claude/known-bugs.md`
Expected: `B9` appears after `B8` and before `## Deferred Refactors`.

- [ ] **Step 3: Commit**

```bash
git add .claude/known-bugs.md
git commit -m "docs(known-bugs): add B9 — HS256 JWT forgery fallback, fixed

Records the root cause, the live evidence, why the path was removed
rather than repaired, and the two items tracked separately (jwt_secret
rotation in H4; ValidateSession trusting the role claim)."
```

---

## Final verification

Run the spec's verification gate before claiming completion:

```bash
go build ./...
go vet ./...
go test ./...
grep -rn "hs256\|HS256\|migrationDeadline\|MigrationWindow\|legacyJWTService\|jwt_secret\|migration_window" --include="*.go" internal/ api/ cmd/ bootstrap/ app/ config/
```

The grep must return only:
- `internal/crypto/crypto_operations.go` + its test (`AlgorithmHS256` — the crypto API's HMAC *key operation*, unrelated to session JWTs);
- `internal/services/auth/jwt_service_provider_test.go` (`leakedJWTSecret`, `forgedHS256Token`, `TestJWTService_Provider_KidlessHS256Token_Rejected`);
- `bootstrap/secrets_initializer.go`'s doc-comment example and `bootstrap/secrets_initializer_test.go`'s generic `ENV → viper key` mapping fixtures, which use `"jwt_secret"` only as an illustrative string.

Anything else is a leftover to clean up.
