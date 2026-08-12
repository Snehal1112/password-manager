# OIDC External Identity Provider — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the identity gap in `.claude/azure-keyvault-parity.md` §6 ("Identity provider: 🟡 Local users + JWT + TOTP MFA (no external IdP)") by adding OIDC (OpenID Connect authorization code flow) as an additional login path, alongside — not replacing — RocketVault's existing local username/password/TOTP login. This mirrors Azure Key Vault's Entra ID model: an external identity provider authenticates the principal, and RocketVault's existing vault-scoped role-assignment system (unchanged by this plan) still governs what that principal can do once authenticated.

**Architecture:** A new `OIDCService` (`internal/services/auth/oidc_service.go`) wraps `github.com/coreos/go-oidc/v3/oidc` + `golang.org/x/oauth2` to build the provider's authorization URL and, on callback, exchange the code and verify the returned ID token. Two new public routes, `GET /oidc/login` and `GET /oidc/callback`, live on the same unauthenticated router that already serves `POST /oauth2/token` (`api.BaseRoutes.OAuth2`) — no new route group needed. CSRF/replay protection uses the standard stateless double-submit pattern: `/oidc/login` sets short-lived `oidc_state`/`oidc_nonce` HttpOnly cookies and redirects to the provider; `/oidc/callback` verifies both against the returned ID token before proceeding. On successful verification, a new `UserService.FindOrCreateExternalUser` looks up (or creates, defaulting to the lowest-privilege `model.RoleUser`) a `model.User` row keyed by two new columns (`auth_provider`, `external_idp_subject`) — local users keep `auth_provider = 'local'` and a `NULL` subject. `AuthenticationService.AuthenticateUser`'s session-issuance tail (create session row, generate JWT+refresh token) is extracted into a shared private helper and exposed as a new `IssueSessionForUser` method, so the OIDC callback reuses exactly the same session/JWT machinery as local login — no parallel token-issuance code path to drift out of sync.

**Tech Stack:** Go, `github.com/coreos/go-oidc/v3/oidc`, `golang.org/x/oauth2` (both new dependencies), SQLite/PostgreSQL.

## Global Constraints

- `go build ./...` and `go vet ./...` must pass after every task.
- This is additive: local username/password/TOTP login (`POST /users/login`) is completely unchanged. Do not modify `AuthenticateUser`'s password/TOTP validation logic — only extract its already-shared tail.
- `password_hash` is `NOT NULL` in the `users` table, but an empty string `''` satisfies that constraint (it is not a literal SQL `NULL`) — externally-authenticated users get `PasswordHash: ""`, `TOTPSecret: ""`, which `PasswordService.ValidatePassword`/`TOTPService.ValidateCode` will safely reject as a normal invalid-credential failure if anyone ever tries local login against such an account. No schema change is needed for either column; only two new columns (`auth_provider`, `external_idp_subject`) are added.
- Every existing implementer of `AuthenticationService` (currently two: `internal/services/auth/authentication_service.go`'s `authenticationService` and `internal/services/retry/retry_auth_service.go`'s `retryAuthenticationService`) must gain the new `IssueSessionForUser` method — do not forget the retry wrapper, it is easy to miss since it lives in a different package.
- OIDC must be fully optional: when `oidc.enabled: false` (the default), the container must not attempt to construct an `oidc.Provider` (which does a network round-trip to the issuer's discovery document at startup) — `GetOIDCService()` returns `nil`, and the two new routes return `503` rather than panicking or blocking server startup on an unreachable IdP.
- The exact `go-oidc`/`oauth2` API surface below reflects the stable, long-established v3/v0 API of these packages from training knowledge, not a live lookup against this environment (no network access here) — Task 1's Step 6 (`go get` + `go build`) is where any drift from a newer major version would surface; fix forward from the compiler error if so, the shapes described here (`oidc.NewProvider`, `provider.Verifier`, `oauth2.Config.AuthCodeURL`/`Exchange`, `token.Extra("id_token")`, `idToken.Claims`) have been stable for years and are not expected to have changed.

---

### Task 1: Config, dependencies, DB migration, and `model.User` fields

**Files:**
- Modify: `go.mod`, `go.sum` (new dependencies)
- Modify: `.rocketvault.yaml` (new `oidc:` config block, disabled by default)
- Modify: `internal/db/db.go` (two new `users` columns, dual-write)
- Modify: `model/user.go` (`User` struct)
- Modify: `internal/repositories/user_repository.go` (interface + `Create`/`Read`/`ReadByUsername`, new `ReadByExternalSubject`)
- Modify: `internal/repositories/mocks/` equivalents / hand-rolled test mocks of `UserRepositoryInterface` (grep `grep -rln "UserRepositoryInterface = " --include="*_test.go"` to find every hand-rolled implementer)

**Interfaces:**
- Produces: `model.User.AuthProvider string`, `model.User.ExternalIDPSubject string` (empty for local users); `UserRepositoryInterface.ReadByExternalSubject(ctx, provider, subject string) (*model.User, error)` — consumed by Task 3's `UserService.FindOrCreateExternalUser`.

- [ ] **Step 1: Add the dependencies**

Run:
```bash
cd /home/numericlabs/data/rocket/rocketvault
go get github.com/coreos/go-oidc/v3@latest golang.org/x/oauth2@latest
go mod tidy
go build ./...
```

Expected: `go.mod`/`go.sum` gain the two new modules (and `golang.org/x/oauth2` may already be an indirect dependency of something else — `go mod tidy` reconciles that); the build still succeeds since nothing references the new packages yet.

- [ ] **Step 2: Add the config block**

In `.rocketvault.yaml`, add near the existing `oauth2:` block:

```yaml
oidc:
  enabled: false
  issuer_url: ""
  client_id: ""
  client_secret: ""
  redirect_url: "http://localhost:8774/api/v1/oidc/callback"
  scopes: ["openid", "profile", "email"]
```

- [ ] **Step 3: Add the `users` table columns**

In `internal/db/db.go`'s `createOptimizedSchema`, change the `users` table definition:

```sql
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
			role TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
```

to:

```sql
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
			role TEXT NOT NULL,
			auth_provider TEXT NOT NULL DEFAULT 'local',
			external_idp_subject TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
```

Immediately after (still inside `createOptimizedSchema`, alongside the other `users` indexes), add:

```sql
		CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_idp ON users(auth_provider, external_idp_subject) WHERE external_idp_subject IS NOT NULL;
```

(This is a SQLite/PostgreSQL-compatible partial unique index — both support `WHERE` on `CREATE UNIQUE INDEX`. It prevents two rows from claiming the same external identity while leaving every local user's `NULL` subject unconstrained.)

- [ ] **Step 4: Mirror both changes into `migrateSchema`**

In `internal/db/db.go`'s `migrateSchema` migrations list, add at the end:

```go
		"ALTER TABLE users ADD COLUMN auth_provider TEXT NOT NULL DEFAULT 'local'",
		"ALTER TABLE users ADD COLUMN external_idp_subject TEXT",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_idp ON users(auth_provider, external_idp_subject) WHERE external_idp_subject IS NOT NULL",
```

- [ ] **Step 5: Update `model.User`**

In `model/user.go`, change:

```go
type User struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"user_name"`
	PasswordHash string    `json:"password_hash"`
	TOTPSecret   string    `json:"totp_secret"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}
```

to:

```go
type User struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"user_name"`
	PasswordHash string    `json:"password_hash"`
	TOTPSecret   string    `json:"totp_secret"`
	Role         string    `json:"role"`
	// AuthProvider is "local" for username/password/TOTP users, or an OIDC
	// provider identifier (e.g. "oidc") for externally-authenticated users.
	AuthProvider string `json:"auth_provider"`
	// ExternalIDPSubject is the external provider's stable subject (`sub`
	// claim) for externally-authenticated users, empty for local users.
	ExternalIDPSubject string    `json:"external_idp_subject,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
}
```

Add near the `Role constants` block:

```go
// AuthProviderLocal identifies a username/password/TOTP user. This is the
// default and the only provider value that existed before OIDC support.
const AuthProviderLocal = "local"

// AuthProviderOIDC identifies a user authenticated via the configured OIDC
// provider.
const AuthProviderOIDC = "oidc"
```

- [ ] **Step 6: Update the repository — interface, `Create`, `Read`, `ReadByUsername`, new `ReadByExternalSubject`**

In `internal/repositories/user_repository.go`, add to `UserRepositoryInterface`:

```go
	// ReadByExternalSubject retrieves a user by external IdP subject. Returns
	// an error if no such user exists.
	ReadByExternalSubject(ctx context.Context, provider, subject string) (*model.User, error)
```

Change `Create`'s INSERT:

```go
	_, err = r.db.ExecContext(
		ctx,
		"INSERT INTO users (id, username, password_hash, totp_secret, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		user.ID.String(), user.Username, user.PasswordHash, user.TOTPSecret, user.Role, user.CreatedAt,
	)
```

to:

```go
	authProvider := user.AuthProvider
	if authProvider == "" {
		authProvider = model.AuthProviderLocal
	}
	var externalSubject any
	if user.ExternalIDPSubject != "" {
		externalSubject = user.ExternalIDPSubject
	}
	_, err = r.db.ExecContext(
		ctx,
		"INSERT INTO users (id, username, password_hash, totp_secret, role, auth_provider, external_idp_subject, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		user.ID.String(), user.Username, user.PasswordHash, user.TOTPSecret, user.Role, authProvider, externalSubject, user.CreatedAt,
	)
```

(`externalSubject any` — passed as Go `nil` rather than an empty string when absent, so it's stored as SQL `NULL` and stays outside the partial unique index, matching local users' existing rows.)

Change `Read`'s query and scan:

```go
	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, username, password_hash, totp_secret, role, created_at FROM users WHERE id = ?",
		id.String(),
	).Scan(&idStr, &user.Username, &user.PasswordHash, &user.TOTPSecret, &user.Role, &user.CreatedAt)
```

to:

```go
	var externalSubject sql.NullString
	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, username, password_hash, totp_secret, role, auth_provider, external_idp_subject, created_at FROM users WHERE id = ?",
		id.String(),
	).Scan(&idStr, &user.Username, &user.PasswordHash, &user.TOTPSecret, &user.Role, &user.AuthProvider, &externalSubject, &user.CreatedAt)
	user.ExternalIDPSubject = externalSubject.String
```

(Insert the `Scan` and the `user.ExternalIDPSubject = externalSubject.String` line right after the existing error-handling block for `err`, before the function continues to parse `idStr`.)

Apply the identical `externalSubject sql.NullString` pattern to `ReadByUsername`'s query/scan.

Add a new method, mirroring `ReadByUsername`'s shape:

```go
// ReadByExternalSubject retrieves a user by (provider, external subject).
// Returns an error if no such user exists.
func (r *UserRepository) ReadByExternalSubject(ctx context.Context, provider, subject string) (*model.User, error) {
	var user model.User
	var idStr string
	var externalSubject sql.NullString

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, username, password_hash, totp_secret, role, auth_provider, external_idp_subject, created_at FROM users WHERE auth_provider = ? AND external_idp_subject = ?",
		provider, subject,
	).Scan(&idStr, &user.Username, &user.PasswordHash, &user.TOTPSecret, &user.Role, &user.AuthProvider, &externalSubject, &user.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user by external subject: %w", err)
	}
	user.ExternalIDPSubject = externalSubject.String

	user.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user ID: %w", err)
	}

	return &user, nil
}
```

- [ ] **Step 7: Write repository tests**

Find the existing test file covering `UserRepository.Create`/`Read`/`ReadByUsername` (grep `grep -rln "func TestUserRepository_Create\|func TestUserRepository_Read" internal/repositories/*_test.go`) and add, mirroring its existing DB-setup helper:

```go
func TestUserRepository_CreateAndReadByExternalSubject(t *testing.T) {
	db := setUpUserRepoTestDB(t) // use this file's existing setup helper name
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newUserRepoTestLogger(t))

	user := &model.User{
		ID: uuid.New(), Username: "oidc-user", PasswordHash: "", TOTPSecret: "",
		Role: model.RoleUser, AuthProvider: model.AuthProviderOIDC, ExternalIDPSubject: "sub-123",
		CreatedAt: time.Now(),
	}
	require.NoError(t, repo.Create(context.Background(), user))

	loaded, err := repo.ReadByExternalSubject(context.Background(), model.AuthProviderOIDC, "sub-123")
	require.NoError(t, err)
	require.Equal(t, user.ID, loaded.ID)
	require.Equal(t, "sub-123", loaded.ExternalIDPSubject)
}

func TestUserRepository_ReadByExternalSubject_NotFound(t *testing.T) {
	db := setUpUserRepoTestDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newUserRepoTestLogger(t))

	_, err := repo.ReadByExternalSubject(context.Background(), model.AuthProviderOIDC, "nonexistent")
	require.Error(t, err)
}

func TestUserRepository_LocalUser_HasEmptyAuthProviderDefaultsToLocal(t *testing.T) {
	db := setUpUserRepoTestDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newUserRepoTestLogger(t))

	user := &model.User{
		ID: uuid.New(), Username: "local-user", PasswordHash: "hash", TOTPSecret: "secret",
		Role: model.RoleUser, CreatedAt: time.Now(), // AuthProvider left as zero value.
	}
	require.NoError(t, repo.Create(context.Background(), user))

	loaded, err := repo.Read(context.Background(), user.ID)
	require.NoError(t, err)
	require.Equal(t, model.AuthProviderLocal, loaded.AuthProvider)
	require.Empty(t, loaded.ExternalIDPSubject)
}
```

Match this test file's actual DB-setup helper and logger-constructor names — do not invent `setUpUserRepoTestDB`/`newUserRepoTestLogger` if the file already has differently-named equivalents.

- [ ] **Step 8: Fix every hand-rolled `UserRepositoryInterface` mock**

Run: `grep -rln "UserRepositoryInterface = " --include="*_test.go" /home/numericlabs/data/rocket/rocketvault`

For each hit, add a `ReadByExternalSubject` stub matching that file's existing style (testify `mock.Mock`-based `m.Called(...)`, or a hand-rolled `panic("unexpected call: ...")`/`return nil, errors.New("not implemented")` depending on what the file already does for `ReadByUsername`).

- [ ] **Step 9: Build and run**

Run: `go build ./... && go vet ./... && go test ./internal/repositories/... ./model/... -v 2>&1 | tail -60`

Expected: clean build, all tests pass.

- [ ] **Step 10: Commit**

```bash
git add go.mod go.sum .rocketvault.yaml internal/db/db.go model/user.go internal/repositories/user_repository.go
git add -u  # every mock file touched in Step 8, plus the new repo tests from Step 7
git commit -m "feat(db): add auth_provider/external_idp_subject columns for OIDC users"
```

---

### Task 2: Extract shared session-issuance in `AuthenticationService`, add `IssueSessionForUser`

**Files:**
- Modify: `internal/services/auth/authentication_service.go`
- Modify: `internal/services/retry/retry_auth_service.go`
- Test: `internal/services/auth/authentication_service_test.go` (or nearest existing file with `TestAuthenticationService_AuthenticateUser_Success`)

**Interfaces:**
- Produces: `AuthenticationService.IssueSessionForUser(ctx context.Context, user *model.User) (*AuthenticationResult, error)` — consumed by Task 5's OIDC callback handler.

- [ ] **Step 1: Write the failing test**

Add to `internal/services/auth/authentication_service_test.go`:

```go
// TestIssueSessionForUser_Success verifies IssueSessionForUser creates a
// session and issues a JWT without requiring password/TOTP, for callers that
// have already established identity out-of-band (OIDC).
func TestIssueSessionForUser_Success(t *testing.T) {
	userRepo := &MockUserRepository{}
	sessionRepo := &MockSessionRepository{}
	jwtSvc := &MockJWTService{}

	user := &model.User{ID: uuid.New(), Username: "oidc-user", Role: model.RoleUser}

	sessionRepo.On("CreateSession", mock.Anything, mock.AnythingOfType("*model.Session")).Return(nil)
	jwtSvc.On("GenerateToken", user.ID, user.Username, user.Role, mock.AnythingOfType("uuid.UUID")).
		Return("access-token", nil)

	svc := NewAuthenticationService(AuthenticationConfig{
		UserRepository:    userRepo,
		SessionRepository: sessionRepo,
		PasswordService:   &MockPasswordService{},
		TOTPService:       &MockTOTPService{},
		JWTService:        jwtSvc,
		Logger:            &logging.Logger{Logger: logrus.New()},
	})

	result, err := svc.IssueSessionForUser(context.Background(), user)
	require.NoError(t, err)
	assert.Equal(t, "access-token", result.Token)
	assert.NotEmpty(t, result.RefreshToken)
	assert.Equal(t, user.ID, result.UserID)
	sessionRepo.AssertExpectations(t)
	jwtSvc.AssertExpectations(t)
}
```

Match the exact mock type names (`MockUserRepository`, `MockSessionRepository`, `MockJWTService`, `MockPasswordService`, `MockTOTPService`) already established in this test file — confirm with `grep -n "^type Mock" internal/services/auth/*_test.go` before writing, and adjust the snippet above to whatever the real names are.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/services/auth/... -run TestIssueSessionForUser_Success -v`

Expected: FAIL (compile error — `IssueSessionForUser` doesn't exist).

- [ ] **Step 3: Extract the shared tail and add `IssueSessionForUser`**

In `internal/services/auth/authentication_service.go`, add to the `AuthenticationService` interface:

```go
	// IssueSessionForUser creates a session and issues an access/refresh
	// token pair for a user whose identity has already been established
	// out-of-band (e.g. a verified OIDC ID token). It performs no
	// password/TOTP check — callers are responsible for having authenticated
	// the user by some other means before calling this.
	IssueSessionForUser(ctx context.Context, user *model.User) (*AuthenticationResult, error)
```

Replace `AuthenticateUser`'s body from the refresh-token generation onward:

```go
	// Generate refresh token (long-lived)
	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		s.logger.LogAuditError(user.ID.String(), "authenticate_user", "failed", "Failed to generate refresh token", err)
		s.logger.WithError(err).Error("Failed to generate refresh token")
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Create session in database first so we have a session.ID for the JWT jti.
	session := &model.Session{
		ID:               uuid.New(),
		UserID:           user.ID,
		RefreshTokenHash: s.hashRefreshToken(refreshToken),
		DeviceInfo:       "",                                 // Can be populated from request context.
		IPAddress:        "",                                 // Can be populated from request context.
		UserAgent:        "",                                 // Can be populated from request context.
		ExpiresAt:        time.Now().Add(7 * 24 * time.Hour), // 7 days
		LastUsedAt:       time.Now(),
		CreatedAt:        time.Now(),
		Revoked:          false,
	}

	if err := s.sessionRepo.CreateSession(ctx, session); err != nil {
		s.logger.LogAuditError(user.ID.String(), "authenticate_user", "failed", "Failed to create session", err)
		s.logger.WithError(err).Error("Failed to create session")
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Generate access token (short-lived) with session.ID as jti for revocation checks.
	accessToken, err := s.jwtService.GenerateToken(user.ID, user.Username, user.Role, session.ID)
	if err != nil {
		s.logger.LogAuditError(user.ID.String(), "authenticate_user", "failed", "Failed to generate JWT token", err)
		s.logger.WithError(err).Error("Failed to generate JWT token")
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Log successful authentication
	s.logger.LogAuditInfo(user.ID.String(), "authenticate_user", "success", "User authenticated successfully")
	s.logger.WithFields(logrus.Fields{
		"username":   username,
		"user_id":    user.ID.String(),
		"role":       user.Role,
		"session_id": session.ID.String(),
	}).Info("User authenticated successfully with session")

	return &AuthenticationResult{
		Token:        accessToken,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Username:     user.Username,
		Role:         user.Role,
	}, nil
}
```

with:

```go
	result, err := s.issueSession(ctx, &user, "authenticate_user")
	if err != nil {
		return nil, err
	}

	s.logger.WithFields(logrus.Fields{
		"username": username,
		"user_id":  user.ID.String(),
		"role":     user.Role,
	}).Info("User authenticated successfully with session")

	return result, nil
}

// issueSession creates a session and issues an access/refresh token pair for
// user. auditAction labels the audit log entries so callers (password login
// vs. OIDC callback) are distinguishable in the audit trail.
func (s *authenticationService) issueSession(ctx context.Context, user *model.User, auditAction string) (*AuthenticationResult, error) {
	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		s.logger.LogAuditError(user.ID.String(), auditAction, "failed", "Failed to generate refresh token", err)
		s.logger.WithError(err).Error("Failed to generate refresh token")
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Create session in database first so we have a session.ID for the JWT jti.
	session := &model.Session{
		ID:               uuid.New(),
		UserID:           user.ID,
		RefreshTokenHash: s.hashRefreshToken(refreshToken),
		DeviceInfo:       "",                                 // Can be populated from request context.
		IPAddress:        "",                                 // Can be populated from request context.
		UserAgent:        "",                                 // Can be populated from request context.
		ExpiresAt:        time.Now().Add(7 * 24 * time.Hour), // 7 days
		LastUsedAt:       time.Now(),
		CreatedAt:        time.Now(),
		Revoked:          false,
	}

	if err := s.sessionRepo.CreateSession(ctx, session); err != nil {
		s.logger.LogAuditError(user.ID.String(), auditAction, "failed", "Failed to create session", err)
		s.logger.WithError(err).Error("Failed to create session")
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Generate access token (short-lived) with session.ID as jti for revocation checks.
	accessToken, err := s.jwtService.GenerateToken(user.ID, user.Username, user.Role, session.ID)
	if err != nil {
		s.logger.LogAuditError(user.ID.String(), auditAction, "failed", "Failed to generate JWT token", err)
		s.logger.WithError(err).Error("Failed to generate JWT token")
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	s.logger.LogAuditInfo(user.ID.String(), auditAction, "success", "Session issued successfully")

	return &AuthenticationResult{
		Token:        accessToken,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Username:     user.Username,
		Role:         user.Role,
	}, nil
}

// IssueSessionForUser creates a session and issues an access/refresh token
// pair for a user whose identity has already been established out-of-band.
func (s *authenticationService) IssueSessionForUser(ctx context.Context, user *model.User) (*AuthenticationResult, error) {
	return s.issueSession(ctx, user, "issue_session_for_user")
}
```

Note `AuthenticateUser` now calls `s.issueSession(ctx, &user, "authenticate_user")` — `user` there is the `model.User` value already read from `s.userRepo.ReadByUsername` earlier in the function (that call returns `model.User`, not `*model.User` — pass `&user`).

- [ ] **Step 4: Update the retry wrapper**

In `internal/services/retry/retry_auth_service.go`, add:

```go
// IssueSessionForUser issues a session with retry logic for database operations
func (s *retryAuthenticationService) IssueSessionForUser(ctx context.Context, user *auth.model.User) (*auth.AuthenticationResult, error) {
```

Wait — `retry_auth_service.go` doesn't import `model` directly today (it only references `auth.AuthenticationResult`/`auth.JWTClaims`). Add `"rocketvault/model"` to its imports, then add:

```go
// IssueSessionForUser issues a session with retry logic for database operations.
func (s *retryAuthenticationService) IssueSessionForUser(ctx context.Context, user *model.User) (*auth.AuthenticationResult, error) {
	var result *auth.AuthenticationResult
	var err error

	retryErr := s.retryService.ExecuteDatabaseOperation(ctx, func() error {
		result, err = s.baseService.IssueSessionForUser(ctx, user)
		return err
	})

	return result, retryErr
}
```

- [ ] **Step 5: Fix every other hand-rolled `AuthenticationService` mock**

Run: `grep -rln "AuthenticationService = " --include="*_test.go" /home/numericlabs/data/rocket/rocketvault`

Add an `IssueSessionForUser` stub to each, matching that file's existing style.

- [ ] **Step 6: Run tests to verify they pass**

Run: `go build ./... && go vet ./... && go test ./internal/services/auth/... ./internal/services/retry/... -v 2>&1 | tail -80`

Expected: all pass, including every pre-existing `AuthenticateUser` test (the refactor must not change its observable behavior — same session/JWT shape, same error messages, same audit action name `"authenticate_user"`).

- [ ] **Step 7: Commit**

```bash
git add internal/services/auth/authentication_service.go internal/services/auth/authentication_service_test.go \
  internal/services/retry/retry_auth_service.go
git add -u  # every mock file touched in Step 5
git commit -m "refactor(auth): extract shared session issuance, add IssueSessionForUser"
```

---

### Task 3: Add `UserService.FindOrCreateExternalUser`

**Files:**
- Modify: `internal/services/users/user_service.go`
- Test: `internal/services/users/user_service_test.go` (or nearest existing file testing `CreateUser`)

**Interfaces:**
- Consumes: `UserRepositoryInterface.ReadByExternalSubject` (Task 1), `UserRepositoryInterface.Create`.
- Produces: `UserService.FindOrCreateExternalUser(ctx context.Context, req FindOrCreateExternalUserRequest) (*model.User, error)` — consumed by Task 5's OIDC callback handler.

- [ ] **Step 1: Write the failing tests**

Add to `internal/services/users/user_service_test.go`:

```go
func TestFindOrCreateExternalUser_ExistingUser_ReturnsIt(t *testing.T) {
	repo := &mockUserRepository{}
	existing := &model.User{ID: uuid.New(), Username: "existing", AuthProvider: model.AuthProviderOIDC, ExternalIDPSubject: "sub-1"}
	repo.On("ReadByExternalSubject", mock.Anything, model.AuthProviderOIDC, "sub-1").Return(existing, nil)

	svc := NewUserService(UserServiceConfig{UserRepository: repo, Logger: &logging.Logger{Logger: logrus.New()}})

	got, err := svc.FindOrCreateExternalUser(context.Background(), FindOrCreateExternalUserRequest{
		Provider: model.AuthProviderOIDC, Subject: "sub-1", PreferredUsername: "existing",
	})
	require.NoError(t, err)
	assert.Equal(t, existing.ID, got.ID)
	repo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestFindOrCreateExternalUser_NewUser_CreatesWithDefaultRole(t *testing.T) {
	repo := &mockUserRepository{}
	repo.On("ReadByExternalSubject", mock.Anything, model.AuthProviderOIDC, "sub-2").
		Return(nil, errors.New("user not found"))
	repo.On("Create", mock.Anything, mock.MatchedBy(func(u *model.User) bool {
		return u.AuthProvider == model.AuthProviderOIDC && u.ExternalIDPSubject == "sub-2" &&
			u.Role == model.RoleUser && u.PasswordHash == "" && u.TOTPSecret == ""
	})).Return(nil)

	svc := NewUserService(UserServiceConfig{UserRepository: repo, Logger: &logging.Logger{Logger: logrus.New()}})

	got, err := svc.FindOrCreateExternalUser(context.Background(), FindOrCreateExternalUserRequest{
		Provider: model.AuthProviderOIDC, Subject: "sub-2", PreferredUsername: "new-user",
	})
	require.NoError(t, err)
	assert.Equal(t, model.RoleUser, got.Role)
	repo.AssertExpectations(t)
}

func TestFindOrCreateExternalUser_UsernameCollision_Suffixes(t *testing.T) {
	repo := &mockUserRepository{}
	repo.On("ReadByExternalSubject", mock.Anything, model.AuthProviderOIDC, "sub-3").
		Return(nil, errors.New("user not found"))
	// First Create attempt collides on username; service must retry with a
	// disambiguated username rather than failing the login outright.
	repo.On("Create", mock.Anything, mock.MatchedBy(func(u *model.User) bool { return u.Username == "taken" })).
		Return(errors.New("username already exists")).Once()
	repo.On("Create", mock.Anything, mock.MatchedBy(func(u *model.User) bool { return u.Username != "taken" })).
		Return(nil).Once()

	svc := NewUserService(UserServiceConfig{UserRepository: repo, Logger: &logging.Logger{Logger: logrus.New()}})

	got, err := svc.FindOrCreateExternalUser(context.Background(), FindOrCreateExternalUserRequest{
		Provider: model.AuthProviderOIDC, Subject: "sub-3", PreferredUsername: "taken",
	})
	require.NoError(t, err)
	assert.NotEqual(t, "taken", got.Username)
	repo.AssertExpectations(t)
}
```

Match this test file's existing mock repository type name (likely `mockUserRepository` or similar — confirm with `grep -n "^type mock" internal/services/users/*_test.go` first) instead of guessing.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/services/users/... -run TestFindOrCreateExternalUser -v`

Expected: FAIL (compile error).

- [ ] **Step 3: Implement `FindOrCreateExternalUser`**

In `internal/services/users/user_service.go`, add to the `UserService` interface:

```go
	// FindOrCreateExternalUser looks up a user by (provider, subject),
	// creating one with the lowest-privilege default role if none exists.
	// Used by the OIDC callback after ID token verification — this method
	// performs no credential check itself.
	FindOrCreateExternalUser(ctx context.Context, req FindOrCreateExternalUserRequest) (*model.User, error)
```

Add the request type near `CreateUserRequest`:

```go
// FindOrCreateExternalUserRequest identifies an externally-authenticated
// principal.
type FindOrCreateExternalUserRequest struct {
	Provider          string // e.g. model.AuthProviderOIDC
	Subject           string // The provider's stable subject (sub claim)
	PreferredUsername string // Best-effort display name; disambiguated on collision
}
```

Add the implementation after `CreateUser`:

```go
// FindOrCreateExternalUser looks up a user by (provider, subject), creating
// one with model.RoleUser (least privilege — an admin must grant vault roles
// separately, exactly as a fresh Entra ID identity has no Key Vault access
// until an RBAC role assignment is made) if none exists.
func (s *userService) FindOrCreateExternalUser(ctx context.Context, req FindOrCreateExternalUserRequest) (*model.User, error) {
	existing, err := s.userRepo.ReadByExternalSubject(ctx, req.Provider, req.Subject)
	if err == nil {
		return existing, nil
	}

	username := req.PreferredUsername
	if username == "" {
		username = req.Subject
	}

	user := &model.User{
		ID:                 uuid.New(),
		Username:           username,
		PasswordHash:       "",
		TOTPSecret:         "",
		Role:               model.RoleUser,
		AuthProvider:        req.Provider,
		ExternalIDPSubject: req.Subject,
		CreatedAt:          time.Now(),
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		// Username collision against an existing *local* user (external
		// subjects are already deduplicated by the lookup above) — retry
		// once with a disambiguated username rather than failing the login.
		user.Username = username + "-" + user.ID.String()[:8]
		if err := s.userRepo.Create(ctx, user); err != nil {
			s.logger.LogAuditError("", "find_or_create_external_user", "failed", "Failed to create externally-authenticated user", err)
			return nil, fmt.Errorf("failed to create user: %w", err)
		}
	}

	s.logger.LogAuditInfo(user.ID.String(), "find_or_create_external_user", "success",
		fmt.Sprintf("Created externally-authenticated user: %s (provider=%s)", user.Username, req.Provider))
	return user, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/services/users/... -run TestFindOrCreateExternalUser -v`

Expected: PASS (3 tests).

- [ ] **Step 5: Regenerate mocks and run the full package suite**

Run: `cd /home/numericlabs/data/rocket/rocketvault && mockery && go build ./... && go vet ./... && go test ./internal/services/users/... -v`

- [ ] **Step 6: Commit**

```bash
git add internal/services/users/user_service.go internal/services/users/user_service_test.go
git add -u
git commit -m "feat(users): add FindOrCreateExternalUser for OIDC-authenticated principals"
```

---

### Task 4: Add `OIDCService`

**Files:**
- Create: `internal/services/auth/oidc_service.go`
- Create: `internal/services/auth/oidc_service_test.go`

**Interfaces:**
- Consumes: `github.com/coreos/go-oidc/v3/oidc`, `golang.org/x/oauth2` (Task 1).
- Produces: `OIDCService` interface with `AuthCodeURL(state, nonce string) string` and `HandleCallback(ctx context.Context, code, expectedNonce string) (*OIDCIdentity, error)` — consumed by Task 5's API handlers.

- [ ] **Step 1: Write the tests**

Create `internal/services/auth/oidc_service_test.go`. Because `oidc.NewProvider` performs a real HTTP discovery-document fetch, these tests use `httptest.NewServer` to serve a minimal OIDC discovery document and JWKS, rather than mocking `OIDCService` itself (there is nothing to mock — this is the boundary service that talks to the real network):

```go
package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// newTestOIDCProvider starts an httptest server serving a minimal OIDC
// discovery document and JWKS so OIDCService can be constructed against it
// without any real network access.
func newTestOIDCProvider(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mux := http.NewServeMux()
	var issuer string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/authorize",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
				"n": jwtBase64URLEncode(key.PublicKey.N.Bytes()),
				"e": jwtBase64URLEncode([]byte{1, 0, 1}),
			}},
		})
	})
	srv := httptest.NewServer(mux)
	issuer = srv.URL
	t.Cleanup(srv.Close)
	return srv, key
}

func jwtBase64URLEncode(b []byte) string {
	return jwt.EncodeSegment(b)
}

func TestOIDCService_AuthCodeURL_IncludesStateAndNonce(t *testing.T) {
	srv, _ := newTestOIDCProvider(t)

	svc, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: srv.URL, ClientID: "client-1", ClientSecret: "secret",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
	})
	require.NoError(t, err)

	url := svc.AuthCodeURL("state-123", "nonce-456")
	require.Contains(t, url, "state=state-123")
	require.Contains(t, url, "nonce=nonce-456")
	require.Contains(t, url, "client_id=client-1")
}

func TestNewOIDCService_UnreachableIssuer_ReturnsError(t *testing.T) {
	_, err := NewOIDCService(context.Background(), OIDCConfig{
		IssuerURL: "http://127.0.0.1:1", ClientID: "x", ClientSecret: "y",
		RedirectURL: "http://localhost/callback", Scopes: []string{"openid"},
	})
	require.Error(t, err)
}
```

(A full `HandleCallback` round-trip test — constructing a real signed ID token, running it through a live token exchange — needs a fake `/token` endpoint too and is materially more setup; Step 1 above covers construction and URL-building, which is what's mechanically testable without a much larger fixture. Task 5's handler tests cover `HandleCallback`'s call sites via a hand-rolled `OIDCService` interface mock instead — see that task.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/services/auth/... -run TestOIDCService -v`

Expected: FAIL (compile error — `NewOIDCService`/`OIDCConfig` don't exist).

- [ ] **Step 3: Implement `OIDCService`**

Create `internal/services/auth/oidc_service.go`:

```go
package auth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCIdentity is the verified identity extracted from an OIDC ID token.
type OIDCIdentity struct {
	Subject           string
	Email             string
	PreferredUsername string
}

// oidcClaims is the subset of standard OIDC claims OIDCService reads from a
// verified ID token.
type oidcClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
}

// OIDCConfig holds OIDCService's configuration.
type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// OIDCService builds the OIDC authorization redirect and verifies the
// resulting ID token on callback.
type OIDCService interface {
	// AuthCodeURL builds the provider's authorization endpoint URL for state
	// and nonce, both of which the caller must independently store (e.g. in
	// short-lived cookies) and re-verify in HandleCallback.
	AuthCodeURL(state, nonce string) string
	// HandleCallback exchanges code for tokens and verifies the returned ID
	// token, including that its nonce claim equals expectedNonce.
	HandleCallback(ctx context.Context, code, expectedNonce string) (*OIDCIdentity, error)
}

type oidcService struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
}

// NewOIDCService fetches the provider's discovery document (a network round
// trip to issuerURL) and returns a ready-to-use OIDCService, or an error if
// the issuer is unreachable or malformed.
func NewOIDCService(ctx context.Context, cfg OIDCConfig) (OIDCService, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to discover issuer %q: %w", cfg.IssuerURL, err)
	}

	return &oidcService{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth2Config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       cfg.Scopes,
		},
	}, nil
}

// AuthCodeURL builds the provider's authorization endpoint URL.
func (s *oidcService) AuthCodeURL(state, nonce string) string {
	return s.oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce))
}

// HandleCallback exchanges code for tokens, verifies the ID token's
// signature and claims (including that its nonce matches expectedNonce), and
// returns the caller's identity.
func (s *oidcService) HandleCallback(ctx context.Context, code, expectedNonce string) (*OIDCIdentity, error) {
	token, err := s.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("oidc: code exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("oidc: token response did not include an id_token")
	}

	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: id_token verification failed: %w", err)
	}

	if idToken.Nonce != expectedNonce {
		return nil, fmt.Errorf("oidc: nonce mismatch")
	}

	var claims oidcClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: failed to parse id_token claims: %w", err)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("oidc: id_token missing sub claim")
	}

	preferredUsername := claims.PreferredUsername
	if preferredUsername == "" {
		preferredUsername = claims.Name
	}

	return &OIDCIdentity{
		Subject:           claims.Subject,
		Email:             claims.Email,
		PreferredUsername: preferredUsername,
	}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/services/auth/... -run TestOIDCService -v -run TestNewOIDCService`

Expected: PASS (2 tests).

- [ ] **Step 5: Run the full auth package suite and commit**

Run: `go build ./... && go vet ./... && go test ./internal/services/auth/... -v 2>&1 | tail -60`

```bash
git add internal/services/auth/oidc_service.go internal/services/auth/oidc_service_test.go
git commit -m "feat(auth): add OIDCService (authorization code flow, ID token verification)"
```

---

### Task 5: Add `GET /oidc/login` and `GET /oidc/callback`

**Files:**
- Create: `api/oidc.go`
- Create: `api/oidc_test.go`
- Modify: `api/api.go` (route registration)
- Modify: `internal/middleware/middleware.go` (`AuthenticationMiddleware` skip list)

**Interfaces:**
- Consumes: `api.App.ServiceContainer.GetOIDCService() authServices.OIDCService` (Task 6), `GetUserService().FindOrCreateExternalUser` (Task 3), `GetAuthenticationService().IssueSessionForUser` (Task 2).
- Produces: `oidcLoginHandler`, `oidcCallbackHandler` — registered as routes, no other code depends on them directly.

- [ ] **Step 1: Write the failing handler tests**

`oidcLoginHandler`/`oidcCallbackHandler` are methods on `*API` (like `tokenHandler`, not `ApiSessionRequired`-wrapped `*Context` handlers), since they live on the same public, unauthenticated `api.BaseRoutes.OAuth2` router. Mirror `api/oauth2_handlers_test.go`'s exact fixture shape for this router kind: a hand-rolled `ServiceContainerInterface` stub type plus a `newOIDCHAPI(...) *API` constructor (see that file's `oauth2HTestContainer`/`newOAuth2HAPI` for the full method list to copy — every method not needed by these tests panics).

Create `api/oidc_test.go`. Since `OIDCService` talks to a real network endpoint, its handler tests use a hand-rolled interface mock (not a live provider):

```go
// Package api — tests for the OIDC login/callback handlers.
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/app"
	authServices "rocketvault/internal/services/auth"
	userServices "rocketvault/internal/services/users"
	"rocketvault/model"
)

type mockOIDCService struct {
	mock.Mock
}

func (m *mockOIDCService) AuthCodeURL(state, nonce string) string {
	args := m.Called(state, nonce)
	return args.String(0)
}

func (m *mockOIDCService) HandleCallback(ctx context.Context, code, expectedNonce string) (*authServices.OIDCIdentity, error) {
	args := m.Called(ctx, code, expectedNonce)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.OIDCIdentity), args.Error(1)
}

type mockUserServiceForOIDC struct {
	mock.Mock
	userServices.UserService
}

func (m *mockUserServiceForOIDC) FindOrCreateExternalUser(ctx context.Context, req userServices.FindOrCreateExternalUserRequest) (*model.User, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

type mockAuthServiceForOIDC struct {
	mock.Mock
	authServices.AuthenticationService
}

func (m *mockAuthServiceForOIDC) IssueSessionForUser(ctx context.Context, user *model.User) (*authServices.AuthenticationResult, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authServices.AuthenticationResult), args.Error(1)
}

// newOIDCHAPI builds an API instance for oidcLoginHandler/oidcCallbackHandler
// tests. Mirror oauth2HTestContainer from api/oauth2_handlers_test.go for the
// full ServiceContainerInterface method list — every method other than
// GetOIDCService/GetUserService/GetAuthenticationService panics.
func newOIDCHAPI(oidcSvc authServices.OIDCService, userSvc userServices.UserService, authSvc authServices.AuthenticationService) *API {
	a := &app.App{ServiceContainer: &oidcHTestContainer{oidcSvc: oidcSvc, userSvc: userSvc, authSvc: authSvc}}
	return &API{App: a, Logger: userTestLog()}
}

func TestOIDCLogin_ServiceUnavailable_Returns503(t *testing.T) {
	api := newOIDCHAPI(nil, nil, nil) // no OIDCService configured
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/login", nil)

	api.oidcLoginHandler(w, r)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestOIDCLogin_SetsStateAndNonceCookiesAndRedirects(t *testing.T) {
	oidcSvc := &mockOIDCService{}
	oidcSvc.On("AuthCodeURL", mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return("https://idp.example.com/authorize?state=x")

	api := newOIDCHAPI(oidcSvc, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/login", nil)

	api.oidcLoginHandler(w, r)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://idp.example.com/authorize?state=x", w.Header().Get("Location"))
	cookies := w.Result().Cookies()
	var sawState, sawNonce bool
	for _, ck := range cookies {
		if ck.Name == "oidc_state" {
			sawState = true
		}
		if ck.Name == "oidc_nonce" {
			sawNonce = true
		}
	}
	assert.True(t, sawState, "oidc_state cookie must be set")
	assert.True(t, sawNonce, "oidc_nonce cookie must be set")
}

func TestOIDCCallback_MissingStateCookie_Returns400(t *testing.T) {
	oidcSvc := &mockOIDCService{}
	api := newOIDCHAPI(oidcSvc, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=x&code=y", nil)

	api.oidcCallbackHandler(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOIDCCallback_StateMismatch_Returns400(t *testing.T) {
	oidcSvc := &mockOIDCService{}
	api := newOIDCHAPI(oidcSvc, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=wrong&code=y", nil)
	r.AddCookie(&http.Cookie{Name: "oidc_state", Value: "expected"})
	r.AddCookie(&http.Cookie{Name: "oidc_nonce", Value: "nonce-1"})

	api.oidcCallbackHandler(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	oidcSvc.AssertNotCalled(t, "HandleCallback", mock.Anything, mock.Anything, mock.Anything)
}

func TestOIDCCallback_Success_ReturnsLoginResponse(t *testing.T) {
	identity := &authServices.OIDCIdentity{Subject: "sub-1", PreferredUsername: "jdoe", Email: "jdoe@example.com"}
	oidcSvc := &mockOIDCService{}
	oidcSvc.On("HandleCallback", mock.Anything, "auth-code", "nonce-1").Return(identity, nil)

	userSvc := &mockUserServiceForOIDC{}
	user := &model.User{ID: uuid.New(), Username: "jdoe", Role: model.RoleUser}
	userSvc.On("FindOrCreateExternalUser", mock.Anything, mock.Anything).Return(user, nil)

	authSvc := &mockAuthServiceForOIDC{}
	authSvc.On("IssueSessionForUser", mock.Anything, user).Return(&authServices.AuthenticationResult{
		Token: "access-token", RefreshToken: "refresh-token", UserID: user.ID, Username: user.Username, Role: user.Role,
	}, nil)

	api := newOIDCHAPI(oidcSvc, userSvc, authSvc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=expected&code=auth-code", nil)
	r.AddCookie(&http.Cookie{Name: "oidc_state", Value: "expected"})
	r.AddCookie(&http.Cookie{Name: "oidc_nonce", Value: "nonce-1"})

	api.oidcCallbackHandler(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	oidcSvc.AssertExpectations(t)
	userSvc.AssertExpectations(t)
	authSvc.AssertExpectations(t)
}
```

This test file needs an `oidcHTestContainer` type: copy `oauth2HTestContainer` from `api/oauth2_handlers_test.go` verbatim (every panicking method), add `oidcSvc authServices.OIDCService`, `userSvc userServices.UserService`, `authSvc authServices.AuthenticationService` fields, and replace its `GetOIDCService`/`GetUserService`/`GetAuthenticationService` methods to return those three fields instead of panicking (every other method keeps panicking).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./api/... -run TestOIDC -v`

Expected: FAIL (compile error — handlers, `newOIDCCtx`, and `GetOIDCService` don't exist yet).

- [ ] **Step 3: Implement the handlers**

Create `api/oidc.go`. `oidcLoginHandler`/`oidcCallbackHandler` are methods on `*API`, exactly like `tokenHandler` in `api/oauth2.go` — they reach the container via `api.App.ServiceContainer`, not a `*Context` (these routes are unauthenticated, so there is no `*Context` yet):

```go
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	userServices "rocketvault/internal/services/users"
	"rocketvault/model"
)

const (
	oidcStateCookie  = "oidc_state"
	oidcNonceCookie  = "oidc_nonce"
	oidcCookieMaxAge = 5 * time.Minute
)

// oidcLoginHandler redirects the caller to the configured OIDC provider's
// authorization endpoint, having first stashed a random state and nonce in
// short-lived cookies for oidcCallbackHandler to verify.
func (api *API) oidcLoginHandler(w http.ResponseWriter, r *http.Request) {
	svc := api.App.ServiceContainer.GetOIDCService()
	if svc == nil {
		http.Error(w, "OIDC is not configured", http.StatusServiceUnavailable)
		return
	}

	state, err := randomOIDCToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := randomOIDCToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	setOIDCCookie(w, oidcStateCookie, state)
	setOIDCCookie(w, oidcNonceCookie, nonce)

	http.Redirect(w, r, svc.AuthCodeURL(state, nonce), http.StatusFound)
}

// oidcCallbackHandler completes the authorization code flow: verifies state,
// exchanges the code, verifies the ID token (including nonce), finds or
// creates the corresponding local user, and issues a session exactly as
// POST /users/login does.
func (api *API) oidcCallbackHandler(w http.ResponseWriter, r *http.Request) {
	svc := api.App.ServiceContainer.GetOIDCService()
	if svc == nil {
		http.Error(w, "OIDC is not configured", http.StatusServiceUnavailable)
		return
	}

	stateCookie, err := r.Cookie(oidcStateCookie)
	if err != nil {
		http.Error(w, "missing or expired oidc_state cookie", http.StatusBadRequest)
		return
	}
	nonceCookie, err := r.Cookie(oidcNonceCookie)
	if err != nil {
		http.Error(w, "missing or expired oidc_nonce cookie", http.StatusBadRequest)
		return
	}

	if r.URL.Query().Get("state") != stateCookie.Value {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code parameter", http.StatusBadRequest)
		return
	}

	identity, err := svc.HandleCallback(r.Context(), code, nonceCookie.Value)
	if err != nil {
		http.Error(w, "oidc callback failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	userSvc := api.App.ServiceContainer.GetUserService()
	if userSvc == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	user, err := userSvc.FindOrCreateExternalUser(r.Context(), userServices.FindOrCreateExternalUserRequest{
		Provider:          model.AuthProviderOIDC,
		Subject:           identity.Subject,
		PreferredUsername: identity.PreferredUsername,
	})
	if err != nil {
		http.Error(w, "failed to resolve user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	authSvc := api.App.ServiceContainer.GetAuthenticationService()
	if authSvc == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	result, err := authSvc.IssueSessionForUser(r.Context(), user)
	if err != nil {
		http.Error(w, "failed to issue session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	clearOIDCCookie(w, oidcStateCookie)
	clearOIDCCookie(w, oidcNonceCookie)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(model.LoginResponse{ //nolint:errcheck,gosec
		Token:        result.Token,
		RefreshToken: result.RefreshToken,
		UserID:       result.UserID.String(),
		Username:     result.Username,
		Role:         result.Role,
	})
}

// randomOIDCToken returns a 32-byte, hex-encoded random token suitable for
// state/nonce values.
func randomOIDCToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func setOIDCCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(oidcCookieMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearOIDCCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}
```

- [ ] **Step 4: Register the routes**

In `api/api.go`, add to `InitOAuth2` (or a new `InitOIDC` called alongside it in `Init`'s registration sequence — match whichever this codebase's convention prefers by checking how `InitJWKS`/`InitConfig` are separated from `InitOAuth2` despite sharing the same public-router pattern; if each public concern gets its own `Init*` method, do the same here):

```go
	api.BaseRoutes.OAuth2.HandleFunc("/oidc/login", api.oidcLoginHandler).Methods("GET")
	api.BaseRoutes.OAuth2.HandleFunc("/oidc/callback", api.oidcCallbackHandler).Methods("GET")
```

- [ ] **Step 5: Update the authentication middleware skip list**

In `internal/middleware/middleware.go`'s `AuthenticationMiddleware`, change:

```go
		if strings.HasSuffix(r.URL.Path, "/health") ||
			strings.HasSuffix(r.URL.Path, "/health/ready") ||
			strings.HasSuffix(r.URL.Path, "/health/live") ||
			strings.HasSuffix(r.URL.Path, "/login") ||
			strings.HasSuffix(r.URL.Path, "/register") ||
			strings.HasSuffix(r.URL.Path, "/refresh") ||
			strings.Contains(r.URL.Path, "/auth/login") ||
			strings.Contains(r.URL.Path, "/auth/register") ||
			strings.Contains(r.URL.Path, "/auth/refresh") ||
			strings.HasSuffix(r.URL.Path, "/oauth2/token") {
```

to:

```go
		if strings.HasSuffix(r.URL.Path, "/health") ||
			strings.HasSuffix(r.URL.Path, "/health/ready") ||
			strings.HasSuffix(r.URL.Path, "/health/live") ||
			strings.HasSuffix(r.URL.Path, "/login") ||
			strings.HasSuffix(r.URL.Path, "/register") ||
			strings.HasSuffix(r.URL.Path, "/refresh") ||
			strings.Contains(r.URL.Path, "/auth/login") ||
			strings.Contains(r.URL.Path, "/auth/register") ||
			strings.Contains(r.URL.Path, "/auth/refresh") ||
			strings.HasSuffix(r.URL.Path, "/oauth2/token") ||
			strings.HasSuffix(r.URL.Path, "/oidc/login") ||
			strings.HasSuffix(r.URL.Path, "/oidc/callback") {
```

(`/oidc/login` already ends in `/login`, matched by the existing `strings.HasSuffix(r.URL.Path, "/login")` clause — the new `/oidc/login` line is technically redundant with it, but add it anyway for clarity/self-documentation and in case the existing generic `/login` suffix match is ever narrowed later; `/oidc/callback` has no existing match and is not redundant.)

- [ ] **Step 6: Run tests to verify they pass**

Run: `go build ./... && go vet ./... && go test ./api/... -run TestOIDC -v`

Expected: PASS (all handler tests).

- [ ] **Step 7: Run the full suite**

Run: `go test ./... 2>&1 | tail -80`

Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add api/oidc.go api/oidc_test.go api/api.go internal/middleware/middleware.go
git commit -m "feat(api): add GET /oidc/login and /oidc/callback"
```

---

### Task 6: Wire `OIDCService` into the service container (optional, config-gated)

**Files:**
- Modify: `internal/container/service_container.go`
- Modify: `internal/container/container_test.go`
- Modify: `cmd/testutils/test_utils.go`

**Interfaces:**
- Produces: `ServiceContainerInterface.GetOIDCService() authServices.OIDCService` — returns `nil` when `oidc.enabled: false` or unset.

- [ ] **Step 1: Add the interface method**

In `internal/container/service_container.go`, add to `ServiceContainerInterface`:

```go
	GetOIDCService() authServices.OIDCService
```

- [ ] **Step 2: Add the field**

Add to the `ServiceContainer` struct:

```go
	oidcService authServices.OIDCService
```

- [ ] **Step 3: Initialize it, gated on `oidc.enabled`**

Near the authentication service initialization block (after `c.authenticationService = ...` is set), add:

```go
	// Initialize OIDC service if configured. This is fully optional: unlike
	// every other service constructed in this method, oidc.NewOIDCService
	// makes a real network call (fetching the issuer's discovery document),
	// so it is skipped entirely — not attempted and swallowed — when
	// oidc.enabled is false or unset, the default.
	if viperCfg.GetBool("oidc.enabled") {
		oidcCfg := authServices.OIDCConfig{
			IssuerURL:    viperCfg.GetString("oidc.issuer_url"),
			ClientID:     viperCfg.GetString("oidc.client_id"),
			ClientSecret: viperCfg.GetString("oidc.client_secret"),
			RedirectURL:  viperCfg.GetString("oidc.redirect_url"),
			Scopes:       viperCfg.GetStringSlice("oidc.scopes"),
		}
		oidcSvc, err := authServices.NewOIDCService(context.Background(), oidcCfg)
		if err != nil {
			c.logger.WithError(err).Warn("Failed to initialise OIDC service; OIDC login will be unavailable")
		} else {
			c.oidcService = oidcSvc
			c.logger.Info("OIDC service initialised")
		}
	}
```

Check whether this method already has `"context"` imported (it almost certainly does, given the number of `context.Background()`-shaped calls elsewhere in container setup) before adding it.

- [ ] **Step 4: Add the getter**

```go
// GetOIDCService returns the OIDC authentication service, or nil if OIDC is
// not configured.
func (c *ServiceContainer) GetOIDCService() authServices.OIDCService {
	return c.oidcService
}
```

- [ ] **Step 5: Update `container_test.go` and `testutils.MockServiceContainer`**

Add a `assert.Nil(t, container.GetOIDCService(), "GetOIDCService")` assertion (OIDC is disabled by default in every test fixture, so it should always be nil in the standard container test) and, in `cmd/testutils/test_utils.go`:

```go
func (m *MockServiceContainer) GetOIDCService() authServices.OIDCService {
	return nil
}
```

- [ ] **Step 6: Fix every other hand-rolled `ServiceContainerInterface` implementer**

Run: `go build ./... 2>&1 | grep "does not implement"` to enumerate every test-only container type across `api/*_test.go` and add a `GetOIDCService` stub to each (panic-on-call, matching that file's convention, exactly as done for `GetKeyRotationPolicyRepository` in the rotation-policy plan).

- [ ] **Step 7: Run the full suite**

Run: `go build ./... && go vet ./... && go test ./... 2>&1 | tail -100`

Expected: clean build, all tests pass.

- [ ] **Step 8: Commit**

```bash
git add internal/container/service_container.go internal/container/container_test.go cmd/testutils/test_utils.go
git add -u
git commit -m "feat(container): wire OIDCService, gated on oidc.enabled"
```

---

### Task 7: Update the parity doc

**Files:**
- Modify: `.claude/azure-keyvault-parity.md`

- [ ] **Step 1: Update §6's identity row**

Change:
```
| Identity provider | Microsoft Entra ID | Local users + JWT (RS256/ES256) + TOTP MFA | 🟡 (no external IdP) |
```
to:
```
| Identity provider | Microsoft Entra ID | Local users + JWT (RS256/ES256) + TOTP MFA, **or** OIDC authorization-code flow (`GET /oidc/login`, `/oidc/callback`) against any standards-compliant IdP (Entra ID, Okta, Auth0, Keycloak, ...); both issue the same RocketVault session/JWT | ✅ (architecture matches: external IdP authenticates, RocketVault's existing vault-scoped role assignments still govern authorization) |
```

- [ ] **Step 2: Update the Summary's Partial (🟡) Identity bullet**

Remove:
```
- **Identity**: local users + TOTP rather than an external IdP.
```

- [ ] **Step 3: Commit**

```bash
git add .claude/azure-keyvault-parity.md
git commit -m "docs(parity): close the external identity provider gap"
```
