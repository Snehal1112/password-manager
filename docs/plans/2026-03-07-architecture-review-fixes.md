# Architecture Review Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Resolve all 27 findings from the 2026-03-07 architecture review, ordered by severity so
the codebase is production-safe before tackling quality improvements.

**Architecture:** Fixes are grouped into six phases — critical security/correctness blockers first,
then testability infrastructure, then service/API layer correctness, then code quality, then
medium-severity issues, and finally low-severity polish. Each phase leaves the project in a
buildable, passing state.

**Tech Stack:** Go 1.24.2, gorilla/mux, logrus, testify/mock, bcrypt, golang-jwt/jwt/v5,
SQLite/PostgreSQL via `database/sql`

**Design doc:** `docs/plans/2026-03-07-architecture-review-design.md`

---

## Phase 1 — Critical: Security & Correctness Blockers

---

### Task 1: Remove committed secrets from git and rotate them

**Finding:** Critical — `master_key`, `jwt_secret`, `bootstrap_token` tracked in git history.

**Files:**
- Modify: `.gitignore`
- Delete from tracking: `.rocketvault.yaml`, `.rocketvault-production.yaml`, `.rocketvault-staging.yaml`

**Step 1: Add config files to .gitignore**

Open `.gitignore` and add after the existing `# Security sensitive files` block:

```
# Config files contain secrets — never commit
.rocketvault*.yaml
```

**Step 2: Remove config files from git tracking (keep local copies)**

```bash
git rm --cached .rocketvault.yaml .rocketvault-production.yaml .rocketvault-staging.yaml
```

Expected: three lines like `rm '.rocketvault.yaml'`

**Step 3: Verify files are still on disk but untracked**

```bash
ls -la .rocketvault*.yaml
git status
```

Expected: files exist locally, `git status` shows them under "Untracked files".

**Step 4: Rotate all three secrets**

Generate new values (run each separately):

```bash
# New master_key (32 bytes, base64)
openssl rand -base64 32

# New jwt_secret (32 bytes, base64)
openssl rand -base64 32

# New bootstrap_token (32 bytes, base64)
openssl rand -base64 32
```

Update `.rocketvault.yaml` with the new values. Update staging and production configs too.

**Step 5: Commit**

```bash
git add .gitignore
git commit -m "security: stop tracking config files containing secrets

Config files with master_key, jwt_secret, and bootstrap_token were
tracked in git. Remove from tracking and gitignore all .rocketvault
yaml variants. Secrets rotated."
```

**Step 6: Purge from git history (do this after verifying the build still works)**

```bash
# Install git-filter-repo if not present: pip install git-filter-repo
git filter-repo --path .rocketvault.yaml --path .rocketvault-production.yaml --path .rocketvault-staging.yaml --invert-paths
```

> **Warning:** This rewrites history. Coordinate with all collaborators before force-pushing.

---

### Task 2: Wire `bootstrap.Shutdown()` into the server lifecycle

**Finding:** Critical — DB pool, cache goroutine, scheduler goroutine leaked on SIGTERM.

**Files:**
- Modify: `bootstrap/bootstrap.go` (lines 151–163, `Boot` function)
- Modify: `server/server.go` (around line 252, after HTTP shutdown)

**Step 1: Read the Boot function**

```bash
sed -n '151,165p' bootstrap/bootstrap.go
sed -n '240,275p' server/server.go
```

**Step 2: Expose Shutdown from Boot**

In `bootstrap/bootstrap.go`, change `Boot` to return a shutdown function alongside the error:

```go
// Boot initialises the application and returns a shutdown function and any setup error.
// Call the shutdown function after the HTTP server has stopped to clean up resources.
func Boot(ctx context.Context, cfg *Config, serverCfg *config.Config) (func(context.Context) error, error) {
    bs := newBootstrap(serverCfg)
    if err := bs.setup(ctx, cfg); err != nil {
        return nil, err
    }
    return bs.Shutdown, nil
}
```

**Step 3: Update the call site in `cmd/serve.go`**

Find the `bootstrap.Boot(...)` call (currently around line 107) and update:

```go
func serve(cmd *cobra.Command) error {
    ctx := cmd.Context()
    log := ctx.Value(common.LogKey).(*logging.Logger)
    bootstrapConfig.Logger = log

    shutdown, err := bootstrap.Boot(ctx, bootstrapConfig, &config.Config{
        Logger: log,
    })
    if err != nil {
        return err
    }
    defer shutdown(ctx)
    return nil
}
```

**Step 4: Build to verify no compile errors**

```bash
go build ./...
```

Expected: no errors (one warning about `*.sql` embed is acceptable for now).

**Step 5: Commit**

```bash
git add bootstrap/bootstrap.go cmd/serve.go
git commit -m "fix: wire bootstrap.Shutdown into serve command lifecycle

Shutdown was defined but never called. DB connection pool, cache
background goroutine, and scheduler goroutine were leaked on SIGTERM.
Boot now returns a shutdown function that serve defers."
```

---

### Task 3: Fix retry service initialisation ordering in service container

**Finding:** Critical — auth service checks `c.retryService != nil` before it is assigned,
so auth service never gets retry wrapping.

**Files:**
- Modify: `internal/container/service_container.go` (function `initializeServices`)

**Step 1: Locate the two relevant blocks**

```bash
grep -n "retryService\|Initialize retry\|Initialize auth" internal/container/service_container.go
```

**Step 2: Move retry service init before auth service init**

Inside `initializeServices()`, restructure so retry is first:

```go
func (c *ServiceContainer) initializeServices() error {
    // 1. Repositories
    c.userRepository = repositories.NewUserRepository(c.db, c.logger)
    // ... (keep all existing repo init lines unchanged)

    // 2. Cache (keep existing cache block unchanged)

    // 3. Retry service — must come before any service that wraps with retry
    if c.viper != nil {
        retrySvc, err := retryServices.NewRetryService(c.viper)
        if err != nil {
            c.logger.WithError(err).Warn("Failed to initialize retry service, continuing without retry")
        } else {
            c.retryService = retrySvc
            c.logger.Info("Retry service initialized successfully")
        }
    } else {
        c.logger.Warn("Viper configuration not provided, retry service unavailable")
    }

    // 4. Authentication services (now c.retryService is set if available)
    c.passwordService = authServices.NewPasswordService()
    c.totpService = authServices.NewTOTPService()
    // ... JWT config block unchanged ...
    baseAuthService := authServices.NewAuthenticationService(...)
    if c.retryService != nil {
        c.authenticationService = retryServices.NewRetryAuthenticationService(baseAuthService, c.retryService)
        c.logger.Info("Retry logic enabled for authentication service")
    } else {
        c.authenticationService = baseAuthService
    }

    // 5. Authorization, user service, secret services — keep existing order
    // ...
    return nil
}
```

**Step 3: Also remove the duplicate retry init block** that currently sits between auth and user
service initialisation (around line 242). Delete those ~12 lines entirely.

**Step 4: Build**

```bash
go build ./...
```

**Step 5: Commit**

```bash
git add internal/container/service_container.go
git commit -m "fix: initialise retry service before auth service in container

c.retryService was always nil when the auth service checked it because
the retry service was initialised 12 lines later. Move retry init to
before any service that wraps with retry logic."
```

---

### Task 4: Fix `generateSecret` handler bypassing the service layer

**Finding:** Critical — `generateSecret` in `api/secrets.go` (line 975) constructs a raw
`domain.Secret` and calls `secretsRepo.Create()` directly, skipping encryption, versioning,
and cache invalidation.

**Files:**
- Modify: `api/secrets.go` (function `generateSecret`, around lines 940–1010)

**Step 1: Read the current handler**

```bash
sed -n '935,1015p' api/secrets.go
```

**Step 2: Replace the raw DB path with the service call**

The `SecretService.GenerateSecret` method already exists. Replace everything after the
`GenerateSecretRequest` is built with a service call:

```go
func generateSecret(c *Context, w http.ResponseWriter, r *http.Request) {
    // ... keep existing request parsing and validation unchanged ...

    if c.App == nil || c.App.ServiceContainer == nil {
        c.Err = common.NewAppError("generateSecret", "Service container not available", nil, "", http.StatusInternalServerError)
        return
    }

    secretService := c.App.ServiceContainer.GetSecretService()
    if secretService == nil {
        c.Err = common.NewAppError("generateSecret", "Secret service not available", nil, "", http.StatusInternalServerError)
        return
    }

    secret, err := secretService.GenerateSecret(r.Context(), secrets.GenerateSecretRequest{
        UserID:       userID,
        Name:         req.Name,
        Length:       req.Length,
        UseSymbols:   req.UseSymbols,
        UseNumbers:   req.UseNumbers,
        UseUppercase: req.UseUppercase,
        UseLowercase: req.UseLowercase,
    })
    if err != nil {
        c.Err = common.NewAppError("generateSecret", "Failed to generate secret", nil, err.Error(), http.StatusInternalServerError)
        return
    }

    // ... keep existing response serialisation unchanged ...
}
```

**Step 3: Remove the unused `db` and `repositories` imports from `api/secrets.go`**

After the change, check which imports are still needed:

```bash
go build ./api/...
```

Remove any import that the compiler flags as unused.

**Step 4: Build**

```bash
go build ./...
```

**Step 5: Commit**

```bash
git add api/secrets.go
git commit -m "fix: route generateSecret through service layer

Handler was bypassing encryption, versioning, and cache invalidation by
calling secretsRepo.Create() directly. Now delegates to
SecretService.GenerateSecret() which handles the full workflow."
```

---

### Task 5: Remove dead DB connections from listSecrets, getSecret, updateSecret

**Finding:** Critical (part 2) — three handlers open a DB connection and immediately close it
without using it, wasting a connection per request.

**Files:**
- Modify: `api/secrets.go` (functions `listSecrets` ~line 572, `getSecret` ~line 648,
  `updateSecret` ~line 720)

**Step 1: For each of the three functions, delete the dead code block**

Find and remove the following pattern (it appears identically in all three):

```go
// DELETE these lines wherever they appear in the three handlers:
database := db.NewRepository(c.Logger)
if err := database.InitializeDB(); err != nil {
    c.Err = common.NewAppError("...", "Failed to initialize database", nil, err.Error(), http.StatusInternalServerError)
    return
}
defer database.GetDB().Close()
```

**Step 2: Remove now-unused imports**

```bash
go build ./api/...
```

Remove `"rocketvault/internal/db"` and `"rocketvault/internal/repositories"` from
`api/secrets.go` imports if the compiler reports them unused.

**Step 3: Build**

```bash
go build ./...
```

**Step 4: Commit**

```bash
git add api/secrets.go
git commit -m "fix: remove dead DB connections from three secret handlers

listSecrets, getSecret, and updateSecret were opening a new database
connection and immediately closing it without using it. Service layer
already has the DB connection via the container."
```

---

## Phase 2 — High: Testability Infrastructure

---

### Task 6: Fix `NewMiddleware` to accept the `Container` interface

**Finding:** High — middleware is untestable without real infrastructure.

**Files:**
- Modify: `internal/middleware/middleware.go` (function `NewMiddleware`, line ~65)
- Modify: `api/api.go` (call site, line ~56)

**Step 1: Change the `NewMiddleware` signature**

```go
// NewMiddleware creates a new middleware with service dependencies.
func NewMiddleware(container Container) *Middleware {
    return &Middleware{
        container: container,
        logger:    container.GetLogger(),
    }
}
```

The `Container` interface is already defined in the same file. This is a one-line change.

**Step 2: Update call site in `api/api.go`**

The call site passes `api.App.ServiceContainer` which implements `Container` — no change
required there. Verify:

```bash
go build ./...
```

**Step 3: Commit**

```bash
git add internal/middleware/middleware.go
git commit -m "fix: NewMiddleware accepts Container interface not concrete type

Allows middleware to be tested with mock implementations.
The Container interface was already defined in the same file."
```

---

### Task 7: Fix migration embed — add placeholder SQL file

**Finding:** High (test blocker) — `//go:embed *.sql` fails because no `.sql` files exist,
blocking tests in the root and `cmd` packages.

**Files:**
- Create: `internal/db/migrations/001_initial_schema.sql`

**Step 1: Create a placeholder migration file**

```bash
cat > internal/db/migrations/001_initial_schema.sql << 'EOF'
-- Initial schema migration placeholder.
-- The production schema is managed in internal/db/db.go.
-- Future migrations should be added here as numbered files.
SELECT 1;
EOF
```

**Step 2: Verify the embed now compiles**

```bash
go build ./internal/db/migrations/...
go build ./...
```

Expected: the `pattern *.sql: no matching files found` warning disappears.

**Step 3: Run the previously failing packages**

```bash
go test ./cmd/... -v 2>&1 | head -20
go test . -v 2>&1 | head -20
```

**Step 4: Commit**

```bash
git add internal/db/migrations/001_initial_schema.sql
git commit -m "fix: add placeholder SQL file to satisfy go:embed directive

The migration_runner.go //go:embed *.sql directive failed at build time
because no .sql files existed, blocking root and cmd package tests."
```

---

### Task 8: Create `internal/testutils` package with shared mocks

**Finding:** High — mock infrastructure in `cmd/testutils` is unreachable from `internal/`
packages (import cycle).

**Files:**
- Create: `internal/testutils/mocks.go`

**Step 1: Create the package with the essential mocks**

```go
// Package testutils provides shared mock implementations for internal package tests.
package testutils

import (
    "context"

    "github.com/google/uuid"
    "github.com/stretchr/testify/mock"

    "rocketvault/internal/domain"
    authServices "rocketvault/internal/services/auth"
    secretServices "rocketvault/internal/services/secrets"
    userServices "rocketvault/internal/services/users"
)

// MockSecretService is a testify mock for SecretService.
type MockSecretService struct {
    mock.Mock
}

func (m *MockSecretService) CreateSecret(ctx context.Context, req secretServices.CreateSecretRequest) (*domain.Secret, error) {
    args := m.Called(ctx, req)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*domain.Secret), args.Error(1)
}

func (m *MockSecretService) GetSecret(ctx context.Context, secretID, userID uuid.UUID) (*domain.Secret, error) {
    args := m.Called(ctx, secretID, userID)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*domain.Secret), args.Error(1)
}

func (m *MockSecretService) ListSecrets(ctx context.Context, userID uuid.UUID, tags []string) ([]domain.Secret, error) {
    args := m.Called(ctx, userID, tags)
    return args.Get(0).([]domain.Secret), args.Error(1)
}

func (m *MockSecretService) UpdateSecret(ctx context.Context, req secretServices.UpdateSecretRequest) error {
    return m.Called(ctx, req).Error(0)
}

func (m *MockSecretService) DeleteSecret(ctx context.Context, secretID, userID uuid.UUID) error {
    return m.Called(ctx, secretID, userID).Error(0)
}

func (m *MockSecretService) GenerateSecret(ctx context.Context, req secretServices.GenerateSecretRequest) (*domain.Secret, error) {
    args := m.Called(ctx, req)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*domain.Secret), args.Error(1)
}

func (m *MockSecretService) ExportSecrets(ctx context.Context, req secretServices.ExportSecretsRequest) ([]byte, error) {
    args := m.Called(ctx, req)
    return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSecretService) ImportSecrets(ctx context.Context, req secretServices.ImportSecretsRequest) (*secretServices.ImportResult, error) {
    args := m.Called(ctx, req)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*secretServices.ImportResult), args.Error(1)
}

func (m *MockSecretService) GetSecretVersions(ctx context.Context, secretID, userID uuid.UUID) ([]domain.SecretVersion, error) {
    args := m.Called(ctx, secretID, userID)
    return args.Get(0).([]domain.SecretVersion), args.Error(1)
}

func (m *MockSecretService) GetSecretVersion(ctx context.Context, secretID uuid.UUID, version int, userID uuid.UUID) (*domain.SecretVersion, error) {
    args := m.Called(ctx, secretID, version, userID)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*domain.SecretVersion), args.Error(1)
}

func (m *MockSecretService) GetLatestSecretVersion(ctx context.Context, secretID, userID uuid.UUID) (*domain.SecretVersion, error) {
    args := m.Called(ctx, secretID, userID)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*domain.SecretVersion), args.Error(1)
}

// MockUserService is a testify mock for UserService.
type MockUserService struct {
    mock.Mock
}

func (m *MockUserService) CreateUser(ctx context.Context, req userServices.CreateUserRequest) (*domain.User, error) {
    args := m.Called(ctx, req)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserService) GetUser(ctx context.Context, id uuid.UUID) (*domain.User, error) {
    args := m.Called(ctx, id)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserService) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
    args := m.Called(ctx, username)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserService) ListUsers(ctx context.Context) ([]domain.User, error) {
    args := m.Called(ctx)
    return args.Get(0).([]domain.User), args.Error(1)
}

func (m *MockUserService) UpdateUser(ctx context.Context, req userServices.UpdateUserRequest) (*domain.User, error) {
    args := m.Called(ctx, req)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserService) DeleteUser(ctx context.Context, id uuid.UUID) error {
    return m.Called(ctx, id).Error(0)
}

func (m *MockUserService) ValidateBootstrapToken(token string) error {
    return m.Called(token).Error(0)
}

func (m *MockUserService) InvalidateBootstrapToken() {
    m.Called()
}

// MockJWTService is a testify mock for JWTService.
type MockJWTService struct {
    mock.Mock
}

func (m *MockJWTService) GenerateToken(claims *domain.Claims) (string, error) {
    args := m.Called(claims)
    return args.String(0), args.Error(1)
}

func (m *MockJWTService) ValidateToken(token string) (*domain.Claims, error) {
    args := m.Called(token)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*domain.Claims), args.Error(1)
}

func (m *MockJWTService) ParseToken(token string) (map[string]any, error) {
    args := m.Called(token)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(map[string]any), args.Error(1)
}

// MockPasswordService is a testify mock for PasswordService.
type MockPasswordService struct {
    mock.Mock
}

func (m *MockPasswordService) HashPassword(password string) (string, error) {
    args := m.Called(password)
    return args.String(0), args.Error(1)
}

func (m *MockPasswordService) ValidatePassword(password, hash string) error {
    return m.Called(password, hash).Error(0)
}

// MockAuthenticationService is a testify mock for AuthenticationService.
type MockAuthenticationService struct {
    mock.Mock
}

func (m *MockAuthenticationService) AuthenticateUser(ctx context.Context, req authServices.AuthRequest) (*authServices.AuthResult, error) {
    args := m.Called(ctx, req)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*authServices.AuthResult), args.Error(1)
}

func (m *MockAuthenticationService) ValidateSession(ctx context.Context, token string) (*domain.Claims, error) {
    args := m.Called(ctx, token)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*domain.Claims), args.Error(1)
}

func (m *MockAuthenticationService) RefreshAccessToken(ctx context.Context, refreshToken string) (*authServices.AuthResult, error) {
    args := m.Called(ctx, refreshToken)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*authServices.AuthResult), args.Error(1)
}

func (m *MockAuthenticationService) RevokeSession(ctx context.Context, sessionID uuid.UUID) error {
    return m.Called(ctx, sessionID).Error(0)
}

func (m *MockAuthenticationService) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID) error {
    return m.Called(ctx, userID).Error(0)
}
```

**Step 2: Build to verify no compile errors**

```bash
go build ./internal/testutils/...
```

**Step 3: Commit**

```bash
git add internal/testutils/mocks.go
git commit -m "feat: add internal/testutils package with shared service mocks

Mocks in cmd/testutils were unreachable from internal packages due to
import cycles. This new package provides the same mock types from a
location internal packages can import."
```

---

## Phase 3 — High: Missing Test Coverage

---

### Task 9: Add unit tests for `SecretService` core operations

**Files:**
- Create: `internal/services/secrets/secret_service_test.go`

**Step 1: Write failing tests**

```go
package secrets_test

import (
    "context"
    "errors"
    "testing"

    "github.com/google/uuid"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
    "github.com/stretchr/testify/require"

    "rocketvault/internal/domain"
    "rocketvault/internal/logging"
    "rocketvault/internal/services/secrets"

    "github.com/sirupsen/logrus"
)

// mockCryptoService satisfies secrets.CryptographyService.
type mockCryptoService struct{ mock.Mock }
func (m *mockCryptoService) EncryptSecret(p string) (string, error) {
    args := m.Called(p); return args.String(0), args.Error(1)
}
func (m *mockCryptoService) DecryptSecret(c string) (string, error) {
    args := m.Called(c); return args.String(0), args.Error(1)
}

// mockSecretRepo satisfies repositories.SecretRepositoryInterface (minimal subset).
type mockSecretRepo struct{ mock.Mock }
func (m *mockSecretRepo) Create(ctx context.Context, s *domain.Secret) error {
    return m.Called(ctx, s).Error(0)
}
func (m *mockSecretRepo) Read(ctx context.Context, id uuid.UUID) (*domain.Secret, error) {
    args := m.Called(ctx, id)
    if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).(*domain.Secret), args.Error(1)
}
func (m *mockSecretRepo) Update(ctx context.Context, s *domain.Secret) error {
    return m.Called(ctx, s).Error(0)
}
func (m *mockSecretRepo) Delete(ctx context.Context, id uuid.UUID) error {
    return m.Called(ctx, id).Error(0)
}
func (m *mockSecretRepo) SoftDelete(ctx context.Context, id uuid.UUID) error {
    return m.Called(ctx, id).Error(0)
}
func (m *mockSecretRepo) ListByUser(ctx context.Context, userID uuid.UUID, tags []string) ([]domain.Secret, error) {
    args := m.Called(ctx, userID, tags)
    return args.Get(0).([]domain.Secret), args.Error(1)
}
// Implement remaining interface methods as empty stubs returning zero values.
func (m *mockSecretRepo) ListByUserIncludeDeleted(ctx context.Context, userID uuid.UUID, tags []string) ([]domain.Secret, error) { return nil, nil }
func (m *mockSecretRepo) ExportSecrets(ctx context.Context, opts domain.ExportOptions) ([]byte, error) { return nil, nil }
func (m *mockSecretRepo) ImportSecrets(ctx context.Context, data []byte, opts domain.ImportOptions) (int, error) { return 0, nil }
func (m *mockSecretRepo) GetVersions(ctx context.Context, id uuid.UUID) ([]domain.SecretVersion, error) { return nil, nil }
func (m *mockSecretRepo) GetVersion(ctx context.Context, id uuid.UUID, v int) (*domain.SecretVersion, error) { return nil, nil }
func (m *mockSecretRepo) GetLatestVersion(ctx context.Context, id uuid.UUID) (*domain.SecretVersion, error) { return nil, nil }
func (m *mockSecretRepo) PurgeSecret(ctx context.Context, id uuid.UUID) error { return nil }

func newTestService(repo *mockSecretRepo, crypto *mockCryptoService) secrets.SecretService {
    logger := &logging.Logger{Logger: logrus.New()}
    return secrets.NewSecretService(secrets.SecretServiceConfig{
        SecretRepository: repo,
        CryptoService:    crypto,
        Logger:           logger,
        // VersionService and TagService intentionally nil for unit tests
        // that only cover Create/Get/List/Delete paths.
    })
}

func TestCreateSecret_Success(t *testing.T) {
    t.Parallel()
    repo := &mockSecretRepo{}
    crypto := &mockCryptoService{}
    svc := newTestService(repo, crypto)

    userID := uuid.New()
    crypto.On("EncryptSecret", "my-value").Return("encrypted-value", nil)
    repo.On("Create", mock.Anything, mock.MatchedBy(func(s *domain.Secret) bool {
        return s.UserID == userID && s.Name == "my-key" && s.Value == "encrypted-value"
    })).Return(nil)

    secret, err := svc.CreateSecret(context.Background(), secrets.CreateSecretRequest{
        UserID: userID,
        Name:   "my-key",
        Value:  "my-value",
    })

    require.NoError(t, err)
    assert.Equal(t, "my-key", secret.Name)
    assert.Equal(t, userID, secret.UserID)
    crypto.AssertExpectations(t)
    repo.AssertExpectations(t)
}

func TestCreateSecret_EncryptionFailure(t *testing.T) {
    t.Parallel()
    repo := &mockSecretRepo{}
    crypto := &mockCryptoService{}
    svc := newTestService(repo, crypto)

    crypto.On("EncryptSecret", mock.Anything).Return("", errors.New("key not configured"))

    _, err := svc.CreateSecret(context.Background(), secrets.CreateSecretRequest{
        UserID: uuid.New(),
        Name:   "key",
        Value:  "value",
    })

    require.Error(t, err)
    repo.AssertNotCalled(t, "Create")
}

func TestGetSecret_NotOwner_ReturnsError(t *testing.T) {
    t.Parallel()
    repo := &mockSecretRepo{}
    crypto := &mockCryptoService{}
    svc := newTestService(repo, crypto)

    ownerID := uuid.New()
    otherUserID := uuid.New()
    secretID := uuid.New()

    stored := &domain.Secret{ID: secretID, UserID: ownerID, Value: "encrypted", Enabled: true}
    repo.On("Read", mock.Anything, secretID).Return(stored, nil)
    crypto.On("DecryptSecret", "encrypted").Return("plaintext", nil)

    _, err := svc.GetSecret(context.Background(), secretID, otherUserID)
    require.Error(t, err)
}

func TestListSecrets_ReturnsDecryptedValues(t *testing.T) {
    t.Parallel()
    repo := &mockSecretRepo{}
    crypto := &mockCryptoService{}
    svc := newTestService(repo, crypto)

    userID := uuid.New()
    stored := []domain.Secret{
        {ID: uuid.New(), UserID: userID, Name: "a", Value: "enc-a", Enabled: true},
        {ID: uuid.New(), UserID: userID, Name: "b", Value: "enc-b", Enabled: true},
    }
    repo.On("ListByUser", mock.Anything, userID, []string(nil)).Return(stored, nil)
    crypto.On("DecryptSecret", "enc-a").Return("plain-a", nil)
    crypto.On("DecryptSecret", "enc-b").Return("plain-b", nil)

    list, err := svc.ListSecrets(context.Background(), userID, nil)
    require.NoError(t, err)
    assert.Len(t, list, 2)
    assert.Equal(t, "plain-a", list[0].Value)
}
```

**Step 2: Run tests — expect them to fail or compile-error first**

```bash
go test ./internal/services/secrets/... -v -run TestCreate 2>&1 | head -30
```

Iterate on compile errors by adjusting mock method signatures to match the actual interfaces.

**Step 3: Run all secret service tests**

```bash
go test ./internal/services/secrets/... -v
```

Expected: all new tests PASS.

**Step 4: Commit**

```bash
git add internal/services/secrets/secret_service_test.go
git commit -m "test: add unit tests for SecretService core operations

Covers CreateSecret (success + encryption failure), GetSecret (ownership
check), and ListSecrets (decryption). Uses mock repo and crypto service."
```

---

### Task 10: Add unit tests for auth service critical paths

**Finding:** High — `ValidateSession`, `RefreshAccessToken`, `RevokeSession` at 0% coverage.

**Files:**
- Modify: `internal/services/auth/authentication_service_test.go`

**Step 1: Read the existing test file structure**

```bash
cat internal/services/auth/authentication_service_test.go | head -60
```

**Step 2: Add tests for the uncovered methods**

Append to the existing test file:

```go
func TestAuthenticationService_ValidateSession_ValidToken(t *testing.T) {
    t.Parallel()
    // Build the service using real sub-services (password, totp, jwt)
    // with a mock user repo and session repo.
    // Set up a session record in the mock session repo.
    // Call ValidateSession with a valid JWT.
    // Assert Claims are returned and no error.
}

func TestAuthenticationService_ValidateSession_ExpiredToken(t *testing.T) {
    t.Parallel()
    // Use a JWT signed with a very short expiry in the past.
    // Assert error is returned.
}

func TestAuthenticationService_RevokeSession_Success(t *testing.T) {
    t.Parallel()
    // Set up a session record. Call RevokeSession.
    // Assert session repo Delete was called.
}

func TestAuthenticationService_RevokeAllUserSessions_Success(t *testing.T) {
    t.Parallel()
    // Set up multiple sessions for a user.
    // Call RevokeAllUserSessions. Assert all sessions deleted.
}
```

Fill in each test body following the pattern of the existing
`TestAuthenticationService_AuthenticateUser_Success` test in the same file.

**Step 3: Run tests**

```bash
go test ./internal/services/auth/... -v
```

Expected: all tests PASS. Coverage should rise above 50%.

**Step 4: Add `JWTService` and `PasswordService` tests**

Create `internal/services/auth/jwt_service_test.go`:

```go
package auth_test

import (
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "rocketvault/internal/domain"
    "rocketvault/internal/services/auth"
)

func TestJWTService_GenerateAndValidate_RoundTrip(t *testing.T) {
    t.Parallel()
    svc := auth.NewJWTService(auth.JWTConfig{
        SecretKey: "dGVzdC1zZWNyZXQta2V5LTMyLWJ5dGVzLWxvbmchISE=", // 32-byte base64
        Issuer:    "test",
        Audience:  "test",
        Expiry:    time.Hour,
    })

    claims := &domain.Claims{Username: "alice", Role: "admin"}
    token, err := svc.GenerateToken(claims)
    require.NoError(t, err)
    assert.NotEmpty(t, token)

    parsed, err := svc.ValidateToken(token)
    require.NoError(t, err)
    assert.Equal(t, "alice", parsed.Username)
}

func TestJWTService_ValidateToken_TamperedToken(t *testing.T) {
    t.Parallel()
    svc := auth.NewJWTService(auth.JWTConfig{
        SecretKey: "dGVzdC1zZWNyZXQta2V5LTMyLWJ5dGVzLWxvbmchISE=",
        Issuer: "test", Audience: "test", Expiry: time.Hour,
    })
    _, err := svc.ValidateToken("not.a.valid.jwt")
    require.Error(t, err)
}
```

**Step 5: Run all auth tests**

```bash
go test ./internal/services/auth/... -v -coverprofile=/tmp/auth.out
go tool cover -func=/tmp/auth.out | grep total
```

**Step 6: Commit**

```bash
git add internal/services/auth/
git commit -m "test: add auth service tests for session validation, JWT, and revocation"
```

---

## Phase 4 — High: API & Code Correctness

---

### Task 11: Fix `api/context.go` JWT duplication

**Finding:** High — JWT validated independently of `JWTService`.

**Files:**
- Modify: `api/context.go` (the inline JWT parse block around line 178)

**Step 1: Read the current context parsing logic**

```bash
sed -n '155,210p' api/context.go
```

**Step 2: Replace inline JWT parsing with service container delegation**

Find the block that calls `jwt.ParseWithClaims(...)` and replaces it:

```go
// Before (remove this block):
token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, errors.New("unexpected signing method")
    }
    return []byte(viper.GetString("jwt_secret")), nil
})

// After:
claims, err := ctx.App.ServiceContainer.GetJWTService().ValidateToken(tokenString)
if err != nil {
    ctx.Err = common.NewAppError("SessionRequired", "Invalid or expired token", nil, err.Error(), http.StatusUnauthorized)
    // write error response and return
    return
}
// use claims directly instead of token.Claims
```

Adjust surrounding code to use the `*domain.Claims` returned by `ValidateToken` instead
of the `jwt.MapClaims` interface.

**Step 3: Remove now-unused imports**

```bash
go build ./api/...
```

Remove `"github.com/golang-jwt/jwt/v5"` and the `viper` import from `api/context.go` if
the compiler flags them.

**Step 4: Build and run all tests**

```bash
go build ./...
go test ./...
```

**Step 5: Commit**

```bash
git add api/context.go
git commit -m "fix: delegate JWT validation in context.go to JWTService

Two independent JWT validation paths existed. context.go was calling
viper.GetString directly and re-parsing tokens. Now delegates to
GetJWTService().ValidateToken() from the service container."
```

---

### Task 12: Fix `sql.ErrNoRows` comparisons across repositories

**Finding:** High — 14 occurrences use `==` instead of `errors.Is`.

**Files:**
- Modify: all files in `internal/repositories/`

**Step 1: Find all occurrences**

```bash
grep -rn "== sql\.ErrNoRows\|!= sql\.ErrNoRows" internal/repositories/
```

**Step 2: Replace all occurrences**

```bash
# Preview first
grep -rn "== sql\.ErrNoRows" internal/repositories/ | wc -l

# Apply (review each file after)
sed -i 's/err == sql\.ErrNoRows/errors.Is(err, sql.ErrNoRows)/g' internal/repositories/*.go
sed -i 's/err != sql\.ErrNoRows/!errors.Is(err, sql.ErrNoRows)/g' internal/repositories/*.go
```

**Step 3: Ensure `errors` is imported in each modified file**

```bash
go build ./internal/repositories/...
```

Add `"errors"` to the import block of any file that doesn't already have it.

**Step 4: Run existing tests**

```bash
go test ./...
```

**Step 5: Commit**

```bash
git add internal/repositories/
git commit -m "fix: use errors.Is(err, sql.ErrNoRows) in all repositories

14 occurrences used == which fails if a driver wraps the sentinel error.
errors.Is correctly unwraps the error chain."
```

---

### Task 13: Wrap bare errors in repositories and key service

**Finding:** High — bare `return err` propagates context-free errors.

**Files:**
- Modify: `internal/repositories/secret_repository.go` (lines 431, 514)
- Modify: `internal/repositories/certificate_repository.go` (lines 450, 517)
- Modify: `internal/repositories/user_repository.go` (line 356)
- Modify: `internal/repositories/key_repository.go` (line 391)
- Modify: `internal/services/keys/key_service.go` (lines 355, 393)

**Step 1: For each file, find the bare returns**

```bash
grep -n "return err$\|return nil, err$" internal/repositories/secret_repository.go
```

**Step 2: Wrap each one**

Example pattern — find the function name surrounding each bare return and wrap:

```go
// Before:
return nil, err

// After (adjust function/operation name to match context):
return nil, fmt.Errorf("SecretRepository.Read: %w", err)
```

**Step 3: Ensure `fmt` is imported in each file**

```bash
go build ./internal/repositories/... ./internal/services/keys/...
```

**Step 4: Run tests**

```bash
go test ./...
```

**Step 5: Commit**

```bash
git add internal/repositories/ internal/services/keys/key_service.go
git commit -m "fix: wrap bare errors with context in repositories and key service

Callers were receiving opaque errors with no call-site context.
Wrapped with fmt.Errorf(\"FunctionName: %w\", err) pattern."
```

---

### Task 14: Fix mixed logging — remove stdlib `log` and unstructured Printf

**Finding:** High — three logging styles coexist.

**Files:**
- Modify: `api/context.go` (lines 114, 242)
- Modify: `api/users.go` (all `Logger.Printf` calls)
- Modify: `api/secrets.go` (all `Logger.Printf` calls)

**Step 1: Replace stdlib `log.Println` calls in `api/context.go`**

```bash
grep -n "log\.Println" api/context.go
```

Replace each with the injected logger. Example:

```go
// Before:
log.Println("Error occurred:", w.Header().Clone())

// After:
c.Logger.WithField("headers", w.Header().Clone()).Error("error occurred")
```

**Step 2: Replace `Logger.Printf` with structured fields in `api/users.go`**

```bash
grep -n "Logger\.Printf" api/users.go
```

Example pattern:

```go
// Before:
c.Logger.Printf("User %s logged in successfully with role %s", username, role)

// After:
c.Logger.WithField("username", username).WithField("role", role).Info("user logged in")
```

Apply the same pattern for all `Printf` occurrences in `api/secrets.go`.

**Step 3: Remove stdlib `log` import from `api/context.go`**

```bash
go build ./api/...
```

**Step 4: Run tests**

```bash
go test ./...
```

**Step 5: Commit**

```bash
git add api/context.go api/users.go api/secrets.go
git commit -m "fix: standardise logging to structured logrus throughout API layer

Removed stdlib log package usage and Printf calls. All log entries now
use WithField/WithFields for consistent structured output."
```

---

### Task 15: Raise bcrypt cost from DefaultCost (10) to 12

**Finding:** High — below OWASP 2024 recommendation.

**Files:**
- Modify: `common/encrypt.go` (line 21)

**Step 1: Write a test to document the cost**

In `common/encrypt_test.go`, add:

```go
func TestHashString_UsesCostAboveDefault(t *testing.T) {
    hash, err := HashString("test-password")
    require.NoError(t, err)

    cost, err := bcrypt.Cost([]byte(hash))
    require.NoError(t, err)
    assert.GreaterOrEqual(t, cost, 12, "bcrypt cost should be at least 12 (OWASP 2024 recommendation)")
}
```

**Step 2: Run — expect FAIL**

```bash
go test ./common/... -v -run TestHashString_UsesCostAboveDefault
```

Expected: FAIL — cost is 10.

**Step 3: Fix the implementation**

In `common/encrypt.go`:

```go
// bcryptCost is the work factor for bcrypt hashing.
// OWASP recommends a minimum of 12 for applications created after 2023.
const bcryptCost = 12

func HashString(input string) (string, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(input), bcryptCost)
    // ...
}
```

**Step 4: Run — expect PASS**

```bash
go test ./common/... -v -run TestHashString_UsesCostAboveDefault
```

**Step 5: Run all tests**

```bash
go test ./...
```

**Step 6: Commit**

```bash
git add common/encrypt.go common/encrypt_test.go
git commit -m "fix: raise bcrypt cost from DefaultCost(10) to 12

OWASP recommends minimum cost 12 for new applications (2024).
Added test to assert cost is at least 12."
```

---

### Task 16: Add request body size limit middleware

**Finding:** High — no `http.MaxBytesReader` applied; DoS vector.

**Files:**
- Modify: `internal/middleware/middleware.go`
- Modify: `api/api.go` (apply the new middleware)

**Step 1: Write a failing test in `internal/middleware/middleware_test.go`**

```go
func TestRequestSizeLimitMiddleware_RejectsOversizedBody(t *testing.T) {
    // Build a request with a body larger than the limit.
    largeBody := bytes.Repeat([]byte("x"), 11*1024*1024) // 11 MB
    req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(largeBody))
    rr := httptest.NewRecorder()

    // Wrap a handler that reads the body.
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        io.ReadAll(r.Body)
        w.WriteHeader(http.StatusOK)
    })

    m := buildTestMiddleware(t) // use existing test helper
    m.RequestSizeLimitMiddleware(handler).ServeHTTP(rr, req)

    assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
}
```

**Step 2: Run — expect FAIL (method doesn't exist yet)**

```bash
go test ./internal/middleware/... -v -run TestRequestSizeLimitMiddleware
```

**Step 3: Implement `RequestSizeLimitMiddleware`**

Add to `internal/middleware/middleware.go`:

```go
const (
    // defaultMaxBodyBytes is the default maximum request body size (10 MB).
    defaultMaxBodyBytes = 10 * 1024 * 1024
    // importMaxBodyBytes is the maximum body size for import endpoints (50 MB).
    importMaxBodyBytes = 50 * 1024 * 1024
)

// RequestSizeLimitMiddleware rejects requests with bodies exceeding the limit.
// Default limit is 10 MB. Import endpoints allow up to 50 MB.
func (m *Middleware) RequestSizeLimitMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        limit := int64(defaultMaxBodyBytes)
        if strings.HasSuffix(r.URL.Path, "/import") {
            limit = importMaxBodyBytes
        }
        r.Body = http.MaxBytesReader(w, r.Body, limit)
        next.ServeHTTP(w, r)
    })
}
```

**Step 4: Apply in `api/api.go` before the existing middleware chain**

In the `api.BaseRoutes["ApiRoot"].Use(...)` call, add `middleware.RequestSizeLimitMiddleware`
as the first middleware.

**Step 5: Run — expect PASS**

```bash
go test ./internal/middleware/... -v
go build ./...
```

**Step 6: Commit**

```bash
git add internal/middleware/middleware.go api/api.go internal/middleware/middleware_test.go
git commit -m "feat: add request body size limit middleware (10MB default, 50MB import)

Prevents DoS via unbounded request body reads. Applied globally before
the auth middleware chain."
```

---

### Task 17: Fix CI Go version mismatch

**Finding:** High — CI runs Go 1.20, project uses 1.24.2.

**Files:**
- Modify: `.github/workflows/go.yml`

**Step 1: Update the workflow**

```yaml
- name: Set up Go
  uses: actions/setup-go@v4
  with:
    go-version-file: 'go.mod'  # always matches what's declared in go.mod
```

Also add linting and security scanning steps:

```yaml
- name: Lint
  uses: golangci/golangci-lint-action@v6
  with:
    version: latest

- name: Security scan
  run: |
    go install golang.org/x/vuln/cmd/govulncheck@latest
    govulncheck ./...

- name: Test with coverage
  run: go test -v -coverprofile=coverage.out ./...

- name: Check coverage threshold
  run: |
    COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
    echo "Coverage: $COVERAGE%"
    # Temporarily low threshold — raise as tests are added
    awk "BEGIN{exit ($COVERAGE < 15)}" || (echo "Coverage below 15%" && exit 1)
```

**Step 2: Commit**

```bash
git add .github/workflows/go.yml
git commit -m "ci: use go-version-file to match go.mod, add lint and security scan

CI was pinned to Go 1.20 while go.mod declares 1.24.2. Now reads version
from go.mod. Added golangci-lint, govulncheck, and coverage gate (15%)."
```

---

## Phase 5 — Medium: Architecture Quality

---

### Task 18: Introduce `TagRepository` — remove raw `*sql.DB` from `TagService`

**Finding:** Medium — `TagService` bypasses the repository pattern.

**Files:**
- Create: `internal/repositories/tag_repository.go`
- Modify: `internal/services/secrets/tag_service.go`
- Modify: `internal/container/service_container.go`

**Step 1: Create `TagRepository` interface and implementation**

```go
// Package repositories provides the tag repository interface and implementation.
package repositories

// TagRepositoryInterface defines tag data access operations.
type TagRepositoryInterface interface {
    AddTags(ctx context.Context, secretID uuid.UUID, tags []string) error
    RemoveTags(ctx context.Context, secretID uuid.UUID, tags []string) error
    RemoveAllTags(ctx context.Context, secretID uuid.UUID) error
    GetTags(ctx context.Context, secretID uuid.UUID) ([]string, error)
    FindSecretsByTags(ctx context.Context, userID uuid.UUID, tags []string) ([]uuid.UUID, error)
}

type tagRepository struct {
    db  *sql.DB
    log *logging.Logger
}

func NewTagRepository(db *sql.DB, log *logging.Logger) TagRepositoryInterface {
    return &tagRepository{db: db, log: log}
}

// Implement each method by moving the SQL from the current TagService implementation.
```

**Step 2: Update `TagService` to accept `TagRepositoryInterface`**

```go
type tagService struct {
    repo repositories.TagRepositoryInterface
    log  *logging.Logger
}

func NewTagService(repo repositories.TagRepositoryInterface, logger *logging.Logger) TagService {
    return &tagService{repo: repo, log: logger}
}
```

**Step 3: Update container to wire `TagRepository`**

In `initializeServices()`:

```go
tagRepo := repositories.NewTagRepository(c.db, c.logger)
c.tagService = secretServices.NewTagService(tagRepo, c.logger)
```

**Step 4: Build**

```bash
go build ./...
```

**Step 5: Commit**

```bash
git add internal/repositories/tag_repository.go internal/services/secrets/tag_service.go internal/container/service_container.go
git commit -m "refactor: introduce TagRepository to remove raw sql.DB from TagService

TagService was the only service that took a raw *sql.DB, bypassing the
repository pattern. Now uses TagRepositoryInterface like all other services."
```

---

### Task 19: Fix scheduler `context.Background()` — use server root context

**Finding:** Medium — scheduler ignores cancellation on shutdown.

**Files:**
- Modify: `internal/services/secrets/scheduler_service.go`

**Step 1: Read the scheduler struct definition**

```bash
grep -n "type schedulerService\|struct\|context\b" internal/services/secrets/scheduler_service.go | head -15
```

**Step 2: Add a `ctx` field to the scheduler and thread it through**

```go
type schedulerService struct {
    // ... existing fields ...
    ctx context.Context // root context from server, cancelled on shutdown
}
```

Update `NewSchedulerService` to accept a `context.Context` parameter.

**Step 3: Replace `context.Background()` in `processAllUserOperations`**

```go
func (s *schedulerService) processAllUserOperations() {
    // Use server root context so cancellation propagates on shutdown.
    ctx := s.ctx
    // ... rest unchanged ...
}
```

**Step 4: Update the container to pass its cache context (already cancellable)**

In `initializeServices()`:

```go
c.schedulerService = secretServices.NewSchedulerService(
    c.rotationService,
    c.versioningService,
    c.userRepository,
    c.secretRepository,
    c.rotationRepository,
    c.logger,
    c.cacheContext, // pass the cancellable server context
)
```

**Step 5: Build and run tests**

```bash
go build ./...
go test ./...
```

**Step 6: Commit**

```bash
git add internal/services/secrets/scheduler_service.go internal/container/service_container.go
git commit -m "fix: thread cancellable context into scheduler service

Scheduler was creating context.Background() per run cycle, ignoring
server shutdown. Now uses a server-scoped context that cancels on exit."
```

---

### Task 20: Fix rate limiter — hoist store creation to constructor

**Finding:** Medium — `memory.NewStore()` created per request; limits never accumulate.

**Files:**
- Modify: `internal/middleware/middleware.go` (`RateLimitMiddleware` and `Middleware` struct)

**Step 1: Write a failing test**

```go
func TestRateLimitMiddleware_LimitsRequests(t *testing.T) {
    m := buildTestMiddleware(t)
    handler := m.RateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))

    req := httptest.NewRequest(http.MethodGet, "/test", nil)
    req.RemoteAddr = "192.0.2.1:1234"

    // Make 61 requests from same IP — the 61st should be rate limited.
    var lastCode int
    for i := 0; i < 61; i++ {
        rr := httptest.NewRecorder()
        handler.ServeHTTP(rr, req)
        lastCode = rr.Code
    }
    assert.Equal(t, http.StatusTooManyRequests, lastCode)
}
```

**Step 2: Run — expect FAIL (store created fresh each request)**

```bash
go test ./internal/middleware/... -v -run TestRateLimitMiddleware
```

**Step 3: Fix — move store and limiter construction to `Middleware` struct**

Add fields:

```go
type Middleware struct {
    container      Container
    logger         *logging.Logger
    defaultLimiter *limiter.Limiter
    authLimiter    *limiter.Limiter
}
```

Initialise in `NewMiddleware`:

```go
store := memory.NewStore()
defaultRate := limiter.Rate{Period: time.Minute, Limit: 60}
authRate := limiter.Rate{Period: time.Minute, Limit: 5}
return &Middleware{
    container:      container,
    logger:         container.GetLogger(),
    defaultLimiter: limiter.New(store, defaultRate),
    authLimiter:    limiter.New(store, authRate),
}
```

Update `RateLimitMiddleware` to use `m.defaultLimiter` and `m.authLimiter` instead of
creating new ones.

**Step 4: Run — expect PASS**

```bash
go test ./internal/middleware/... -v
```

**Step 5: Commit**

```bash
git add internal/middleware/middleware.go internal/middleware/middleware_test.go
git commit -m "fix: hoist rate limiter store to middleware constructor

Store was created per-request so counts never accumulated and rate
limiting had no effect. Limiters now persist for the server lifetime."
```

---

### Task 21: Fix conditional HSTS and make JWT TTL configurable

**Finding:** Medium (HSTS) + Low (JWT TTL). Grouped for efficiency.

**Files:**
- Modify: `internal/middleware/middleware.go`
- Modify: `internal/container/service_container.go`

**Step 1: Make HSTS conditional on TLS**

Add a `TLSEnabled` field to the `Middleware` struct:

```go
type Middleware struct {
    // ...
    tlsEnabled bool
}
```

Pass it from `NewMiddleware`. In the security headers section:

```go
if m.tlsEnabled {
    w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
}
```

Update `api/api.go` to pass TLS state from config.

**Step 2: Make JWT TTL configurable**

In `internal/container/service_container.go`, replace the hardcoded expiry:

```go
expiry := viper.GetDuration("jwt.expiry")
if expiry == 0 {
    expiry = time.Hour // default
}
jwtConfig := authServices.JWTConfig{
    SecretKey: c.viper.GetString("jwt_secret"), // use injected viper, not global
    Issuer:    "PasswordManager",
    Audience:  "PASSWORD_MANAGER",
    Expiry:    expiry,
}
```

Note: also fixes the `viper.GetString("jwt_secret")` global-viper call by switching to
`c.viper.GetString(...)` (the injected instance).

**Step 3: Build**

```bash
go build ./...
```

**Step 4: Commit**

```bash
git add internal/middleware/middleware.go internal/container/service_container.go
git commit -m "fix: conditional HSTS header and configurable JWT TTL

HSTS was set unconditionally breaking HTTP-only dev environments.
JWT expiry was hardcoded to 1h; now reads jwt.expiry from config.
Also fixed global viper.GetString for jwt_secret to use injected viper."
```

---

### Task 22: Remove unused MongoDB from docker-compose

**Finding:** Medium — unused service adds noise and startup cost.

**Files:**
- Modify: `docker-compose.yml`

**Step 1: Remove the `mongodb` service and `mongo_data` volume**

Delete the `mongodb:` block and the `mongo_data:` volume entry.

**Step 2: Verify compose file is valid**

```bash
docker-compose config --quiet 2>&1
```

Expected: no errors.

**Step 3: Commit**

```bash
git add docker-compose.yml
git commit -m "chore: remove unused MongoDB service from docker-compose

The codebase has no MongoDB driver or connection code. This removes
misleading infrastructure from the compose file."
```

---

## Phase 6 — Low: Polish

---

### Task 23: Replace `interface{}` with `any`

**Finding:** Low — pre-Go-1.18 style on a Go 1.25 project.

**Files:**
- Modify: `internal/crypto/key_crypto.go`
- Modify: `internal/health/health.go`
- Modify: `internal/logging/yaml.go`

**Step 1: Find all occurrences**

```bash
grep -rn "interface{}" internal/crypto/ internal/health/ internal/logging/ | grep -v "_test.go"
```

**Step 2: Replace**

```bash
sed -i 's/interface{}/any/g' internal/crypto/key_crypto.go internal/health/health.go internal/logging/yaml.go
```

**Step 3: Build and test**

```bash
go build ./...
go test ./...
```

**Step 4: Commit**

```bash
git add internal/crypto/key_crypto.go internal/health/health.go internal/logging/yaml.go
git commit -m "chore: replace interface{} with any (Go 1.18+ idiom)"
```

---

### Task 24: Add `X-Request-ID` propagation

**Finding:** Low — no request correlation between HTTP and DB log entries.

**Files:**
- Modify: `internal/middleware/middleware.go`
- Modify: `common/` (add `RequestIDKey` context key)

**Step 1: Add context key**

In `common/` (alongside existing `UserIDKey`), add:

```go
// RequestIDKey is the context key for the request ID.
const RequestIDKey contextKey = "request_id"
```

**Step 2: Add middleware**

```go
// RequestIDMiddleware generates or forwards a unique request ID per request.
// The ID is taken from X-Request-ID header if present, otherwise generated.
func (m *Middleware) RequestIDMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        requestID := r.Header.Get("X-Request-ID")
        if requestID == "" {
            requestID = uuid.New().String()
        }
        w.Header().Set("X-Request-ID", requestID)
        ctx := context.WithValue(r.Context(), common.RequestIDKey, requestID)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

**Step 3: Apply before all other middleware in `api/api.go`**

Add `middleware.RequestIDMiddleware` as the first entry in the `Use(...)` call.

**Step 4: Update `LoggingMiddleware` to include request ID in log fields**

```go
requestID, _ := r.Context().Value(common.RequestIDKey).(string)
logFields := logrus.Fields{
    "request_id": requestID,
    // ... existing fields ...
}
```

**Step 5: Build and test**

```bash
go build ./...
go test ./...
```

**Step 6: Commit**

```bash
git add internal/middleware/middleware.go common/ api/api.go
git commit -m "feat: add X-Request-ID propagation middleware

Generates a UUID request ID if not provided by caller. Propagates via
context. Included in all structured log entries for correlation."
```

---

### Task 25: Add `t.Parallel()` to all table-driven tests

**Finding:** Low — suite will slow as coverage grows.

**Files:**
- Modify: all `*_test.go` files with table-driven tests

**Step 1: Find all test functions without `t.Parallel()`**

```bash
grep -rn "func Test" --include="*_test.go" -l | xargs grep -L "t.Parallel()"
```

**Step 2: For each table-driven test, add `t.Parallel()` at the top of the function
and `t.Parallel()` inside each sub-test**

```go
func TestSomething(t *testing.T) {
    t.Parallel()  // add this
    tests := []struct{ ... }{ ... }
    for _, tt := range tests {
        tt := tt // capture range variable
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()  // add this inside each sub-test
            // ...
        })
    }
}
```

**Step 3: Run tests to confirm no race conditions**

```bash
go test -race ./...
```

**Step 4: Commit**

```bash
git add $(git diff --name-only)
git commit -m "test: add t.Parallel() to all table-driven tests"
```

---

## Final Verification

After all tasks are complete, run the full validation suite:

```bash
# Build
go build ./...

# All tests with race detector
go test -race -coverprofile=/tmp/final.out ./...

# Coverage report
go tool cover -func=/tmp/final.out | grep total

# Security scan
govulncheck ./...
```

**Expected outcomes:**
- Zero build errors
- All tests pass with `-race`
- Coverage above 40% (from 17%)
- No known vulnerabilities reported

---

## Task Order Summary

| # | Task | Severity | Phase |
|---|------|----------|-------|
| 1 | Remove committed secrets | Critical | 1 |
| 2 | Wire bootstrap.Shutdown() | Critical | 1 |
| 3 | Fix retry init ordering | Critical | 1 |
| 4 | Fix generateSecret handler | Critical | 1 |
| 5 | Remove dead DB in 3 handlers | Critical | 1 |
| 6 | Fix NewMiddleware interface | High | 2 |
| 7 | Fix migration embed | High | 2 |
| 8 | Create internal/testutils | High | 2 |
| 9 | SecretService tests | High | 3 |
| 10 | Auth service critical path tests | High | 3 |
| 11 | Fix JWT duplication in context.go | High | 4 |
| 12 | Fix sql.ErrNoRows comparisons | High | 4 |
| 13 | Wrap bare errors | High | 4 |
| 14 | Fix mixed logging | High | 4 |
| 15 | Raise bcrypt cost to 12 | High | 4 |
| 16 | Add body size limit middleware | High | 4 |
| 17 | Fix CI Go version + add gates | High | 4 |
| 18 | Introduce TagRepository | Medium | 5 |
| 19 | Fix scheduler context | Medium | 5 |
| 20 | Fix rate limiter store | Medium | 5 |
| 21 | Conditional HSTS + JWT TTL config | Medium+Low | 5 |
| 22 | Remove MongoDB from compose | Medium | 5 |
| 23 | Replace interface{} with any | Low | 6 |
| 24 | Add X-Request-ID propagation | Low | 6 |
| 25 | Add t.Parallel() to tests | Low | 6 |
