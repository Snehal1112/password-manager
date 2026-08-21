# B35 Rotation Corruption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make secret rotation write a real, correctly encrypted replacement value that still decrypts afterwards, and archive the value it replaces, on both the manual and the scheduled path.

**Architecture:** `PerformManualRotation` stops inventing a value by string-concatenating onto stored ciphertext. It takes the replacement from the caller (`NewValue`) or generates one on request (`Generate` + `pwgen.Options`), archives the current value through the versioning service, encrypts the replacement through the `CryptographyService` that was already injected and never called, and only then writes. The scheduler asks for generation and drops its own `CreateVersion` call, since the rotation service now owns versioning for both paths.

**Tech Stack:** Go 1.24.2, `internal/pwgen`, testify, SQLite (in-memory) for the round-trip tests.

**Spec:** `docs/superpowers/specs/2026-08-21-cli-bug-fixes-b35-b41-design.md`

## Global Constraints

- Go 1.24.2. Do not raise the version floor.
- **No new module dependencies.**
- Comments are short, full sentences ending in a punctuation mark.
- Every fix starts with a failing test (spec § Testing).
- Rotation never invents a value: neither `NewValue` nor `Generate` is an error, never a silent default (spec § B35, step 1).
- Never log, print, or include a secret plaintext in an error message.
- `cmd/help_examples_test.go` guards help text: every flag named in an `Example` block must be registered on that command or inherited, or the test fails.
- Help text follows `.claude/cli-help-conventions.md`; data actions are written in full, exactly as declared in `model/azure_roles.go`.
- **No repair or re-encryption tooling for already-corrupted secrets** (spec § Non-goals). This plan documents what is and is not recoverable; see "Recovery for already-corrupted secrets" below.
- No changes to the prose docs (`docs/cli-guide.md` and friends); those are a separate pass. In-code help text is in scope.
- **Depends on plan `docs/superpowers/plans/2026-08-21-00-shared-foundations.md` being complete**: `internal/pwgen` must exist with `Options`, `DefaultOptions()` and `Generate(opts) (string, error)`.

## Recovery for already-corrupted secrets

State this plainly; do not imply a clean upgrade.

- **Scheduler-rotated values are recoverable, but not through a normal read.**
  `performAutomaticRotation` calls `versioningSvc.CreateVersion` *before*
  rotating, so a row exists in `secret_versions` for the pre-rotation value.
  That row is **doubly encrypted**: the scheduler passed
  `secret.Value` — already master-key ciphertext — and `CreateVersion` encrypts
  whatever it is given. `secrets versions get` therefore returns the *inner
  ciphertext*, not the plaintext. Recovering the real value means decrypting
  that output a second time with the master key. It is recoverable; it is not
  usable as-is.
- **Manually rotated values are not recoverable.** `PerformManualRotation`
  never versioned anything, and it overwrote `secrets.value` in place with
  `<ciphertext>_rotated_<unix>`. The original ciphertext is destroyed. There is
  no version row, no backup inside RocketVault, and no key that recovers it.
  The only recovery is an out-of-band copy: a database backup taken before the
  rotation, a `rocketvault backup` archive, or the value as known to the system
  the secret belongs to.
- **Detecting affected secrets**: a corrupted value has a `_rotated_<digits>`
  suffix on an otherwise base64 body, and fails to decrypt. Operators can find
  candidates with
  `SELECT id, name FROM secrets WHERE value LIKE '%\_rotated\_%' ESCAPE '\';`
  and cross-check `rotation_history` for `triggered_by = 'manual'`.
- This plan builds no tooling for any of the above. It fixes the defect so no
  new secret is corrupted.

---

### Task 1: Re-rate B35 High → Critical

**Files:**
- Modify: `.claude/known-bugs.md` (lines 1750-1753)

**Interfaces:**
- Consumes: nothing.
- Produces: nothing.

The severity as filed understates the defect: `performAutomaticRotation`
delegates to the same function, so any policy with `AutoRotate: true` corrupts
its secrets unattended, on a timer.

- [ ] **Step 1: Re-rate the entry**

In `.claude/known-bugs.md`, replace lines 1750-1753:

```
**Status**: Open, found 2026-08-21
**Severity**: High — silent data loss. A routine, advertised operation destroys
the secret it claims to rotate, and nothing surfaces an error
**Files**: `internal/services/secrets/rotation_service.go`
```

with:

```
**Status**: Open, found 2026-08-21
**Severity**: Critical — unattended silent data loss. Re-rated from High on
2026-08-21: `schedulerService.performAutomaticRotation`
(`internal/services/secrets/scheduler_service.go:240-247`) delegates to the same
`PerformManualRotation`, so every policy with `AutoRotate: true` destroys its
secrets on a timer with no operator present and no error surfaced. The manual
path is additionally unrecoverable, because it never archives a version row
**Files**: `internal/services/secrets/rotation_service.go`,
`internal/services/secrets/scheduler_service.go`, `cmd/rotation.go`
```

- [ ] **Step 2: Verify the file still reads correctly**

Run: `sed -n '1746,1760p' .claude/known-bugs.md`
Expected: the B35 heading followed by the new Status/Severity/Files block, with
the `**Symptom**` paragraph intact below it.

- [ ] **Step 3: Commit**

```bash
git add .claude/known-bugs.md
git commit -m "docs(bugs): re-rate B35 from High to Critical

The scheduler delegates to the same corrupting function, so any policy
with auto-rotate enabled destroys its secrets unattended, on a timer."
```

---

### Task 2: Inject the versioning service into `rotationService`

**Files:**
- Modify: `internal/services/secrets/rotation_service.go` (struct l.96-103, `NewRotationService` l.111-130)
- Modify: `internal/container/service_container.go` (l.474-481)
- Modify: `internal/services/secrets/rotation_service_test.go` (call sites l.125, 146, 167, 187, 209, 305, 364)
- Modify: `internal/services/secrets/coverage_boost_test.go` (call sites l.887, 976, 1076)
- Modify: `internal/services/secrets/direct_write_invalidation_test.go` (call sites l.112, 149, 238)

**Interfaces:**
- Consumes: `secrets.VersioningServiceInterface` (already defined in
  `internal/services/secrets/versioning_service.go:21`).
- Produces:
  ```go
  func NewRotationService(
      rotationRepo repositories.RotationPolicyRepositoryInterface,
      secretRepo repositories.SecretRepositoryInterface,
      userRepo repositories.UserRepositoryInterface,
      cryptoSvc CryptographyService,
      versioningSvc VersioningServiceInterface,
      log *logging.Logger,
      cacheInv SecretCacheInvalidator,
  ) RotationServiceInterface
  ```

`PerformManualRotation` must archive the value it replaces, and the dependency
that does that is not wired in yet. This task is a pure wiring change with no
behavior change, so it lands on its own and stays green. The container already
constructs `c.versioningService` at l.465, above `c.rotationService` at l.474,
so the ordering needs no rearrangement and there is no dependency cycle
(`versioningService` does not depend on `rotationService`).

- [ ] **Step 1: Add the field and the constructor parameter**

In `internal/services/secrets/rotation_service.go`, change the struct at l.96-103 to:

```go
// rotationService implements RotationServiceInterface.
type rotationService struct {
	rotationRepo  repositories.RotationPolicyRepositoryInterface
	secretRepo    repositories.SecretRepositoryInterface
	userRepo      repositories.UserRepositoryInterface
	cryptoSvc     CryptographyService
	versioningSvc VersioningServiceInterface
	cacheInv      SecretCacheInvalidator
	log           *logging.Logger
}
```

and the constructor at l.111-130 to:

```go
func NewRotationService(
	rotationRepo repositories.RotationPolicyRepositoryInterface,
	secretRepo repositories.SecretRepositoryInterface,
	userRepo repositories.UserRepositoryInterface,
	cryptoSvc CryptographyService,
	versioningSvc VersioningServiceInterface,
	log *logging.Logger,
	cacheInv SecretCacheInvalidator,
) RotationServiceInterface {
	if cacheInv == nil {
		cacheInv = noopSecretCacheInvalidator{}
	}
	return &rotationService{
		rotationRepo:  rotationRepo,
		secretRepo:    secretRepo,
		userRepo:      userRepo,
		cryptoSvc:     cryptoSvc,
		versioningSvc: versioningSvc,
		cacheInv:      cacheInv,
		log:           log,
	}
}
```

Also extend the constructor's doc comment (l.105-110) with one sentence:

```go
// versioningSvc archives the pre-rotation value: rotation must never overwrite
// a secret it has not first written to a version row.
```

- [ ] **Step 2: Verify the build breaks where expected**

Run: `go build ./... 2>&1 | head -20`
Expected: FAIL — `not enough arguments in call to secretServices.NewRotationService`
at `internal/container/service_container.go:474`.

- [ ] **Step 3: Update the container**

In `internal/container/service_container.go`, change l.474-481 to:

```go
	c.rotationService = secretServices.NewRotationService(
		c.rotationRepository,
		c.secretRepository,
		c.userRepository,
		c.cryptoService,
		c.versioningService,
		c.logger,
		secretCacheInvalidator,
	)
```

- [ ] **Step 4: Confirm the production build is clean**

Run: `go build ./...`
Expected: PASS, no output.

- [ ] **Step 5: Update the test call sites**

Insert one `nil` argument for `versioningSvc`, immediately after the crypto
argument, at every remaining call site. Nothing calls the new dependency yet,
so `nil` is safe here; Task 3 replaces `nil` with a real value at the three
sites that exercise rotation.

`internal/services/secrets/rotation_service_test.go` — lines 125, 146, 167, 187, 209:

```go
	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, nil, testutils.NewTestLogger(t), nil)
```

`internal/services/secrets/rotation_service_test.go` — lines 305 and 364:

```go
	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, nil, log, nil)
```

`internal/services/secrets/coverage_boost_test.go` — line 887:

```go
	svc := secrets.NewRotationService(repo, secretRepo, userRepo, crypto, nil, testutils.NewTestLogger(t), nil)
```

line 976:

```go
	svc := secrets.NewRotationService(repo, secretRepo, userRepo, crypto, nil, testutils.NewTestLogger(t), &recordingInvalidator{})
```

line 1076:

```go
	svc := secrets.NewRotationService(repo, secretRepo, userRepo, crypto, nil, testutils.NewTestLogger(t), nil)
```

`internal/services/secrets/direct_write_invalidation_test.go` — lines 112 and 238:

```go
	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, nil, logger, invalidator)
```

line 149:

```go
	svc := secrets.NewRotationService(&mockRotationPolicyRepo{}, secretRepo, nil, nil, nil, logger, invalidator)
```

- [ ] **Step 6: Run the affected packages**

Run:
```bash
go build ./...
go test ./internal/services/secrets/ ./internal/container/
gofmt -l internal/services/secrets internal/container
go vet ./internal/services/secrets/ ./internal/container/
```
Expected: all pass, `gofmt` silent. Behavior is unchanged, so no test should
change its result.

- [ ] **Step 7: Commit**

```bash
git add internal/services/secrets/rotation_service.go internal/container/service_container.go internal/services/secrets/rotation_service_test.go internal/services/secrets/coverage_boost_test.go internal/services/secrets/direct_write_invalidation_test.go
git commit -m "refactor(rotation): inject the versioning service into rotationService

Rotation must archive the value it replaces, which needs the versioning
service. Wiring only; no behavior change yet."
```

---

### Task 3: A real replacement value, correctly encrypted, with the old one archived

**Files:**
- Create: `internal/services/secrets/rotation_roundtrip_test.go`
- Modify: `internal/services/secrets/rotation_service.go` (`ManualRotationRequest` l.79-85, `PerformManualRotation` l.359-436, delete `generateNewSecretValue` l.539-545)
- Modify: `internal/services/secrets/direct_write_invalidation_test.go` (l.89-127 and l.213-250)
- Modify: `internal/services/secrets/coverage_boost_test.go` (l.1004-1019, l.1142-1151)

**Interfaces:**
- Consumes:
  ```go
  package pwgen
  type Options struct { Length int; Upper, Lower, Numbers, Special bool }
  func DefaultOptions() Options
  func Generate(opts Options) (string, error)
  ```
  and `VersioningServiceInterface.CreateVersion(ctx, CreateVersionRequest) (*model.SecretVersion, error)`,
  `CryptographyService.EncryptSecret/DecryptSecret`.
- Produces:
  ```go
  type ManualRotationRequest struct {
      SecretID     uuid.UUID
      PolicyID     uuid.UUID
      Scope        model.Scope
      Notes        string
      NewValue     string
      Generate     bool
      GenerateOpts pwgen.Options
  }

  var ErrRotationValueRequired = errors.New("rotation requires a new value: set NewValue or Generate")
  var ErrRotationValueConflict = errors.New("rotation cannot take both an explicit value and a generated one")
  ```

- [ ] **Step 1: Write the failing round-trip test**

Create `internal/services/secrets/rotation_roundtrip_test.go`. These tests wire
the **real** repositories and the **real** cryptography service over an
in-memory SQLite database on purpose: the defect is a mismatch between what is
stored and what can be decrypted, and a mocked `CryptographyService` cannot
show it — which is exactly why this bug shipped.

```go
package secrets_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/pwgen"
	"rocketvault/internal/repositories"
	"rocketvault/internal/services/secrets"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// rotationFixtureSchema mirrors internal/db/db.go's createOptimizedSchema for
// only the tables rotation touches.
const rotationFixtureSchema = `
	CREATE TABLE users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		totp_secret TEXT,
		role TEXT NOT NULL,
		auth_provider TEXT NOT NULL DEFAULT 'local',
		external_idp_subject TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE secrets (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		vault_id TEXT NOT NULL,
		value TEXT NOT NULL,
		version INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		content_type TEXT NOT NULL DEFAULT '',
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		expires_at TIMESTAMP NULL,
		not_before TIMESTAMP NULL
	);
	CREATE TABLE secret_tags (
		secret_id TEXT NOT NULL,
		tag TEXT NOT NULL,
		PRIMARY KEY (secret_id, tag)
	);
	CREATE TABLE secret_versions (
		id TEXT PRIMARY KEY,
		secret_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		value TEXT NOT NULL,
		version INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE rotation_policies (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		vault_id TEXT NOT NULL,
		name TEXT NOT NULL,
		description TEXT,
		interval_days INTEGER NOT NULL,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		reminder_days INTEGER NOT NULL DEFAULT 7,
		auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE secret_policies (
		secret_id TEXT NOT NULL,
		policy_id TEXT NOT NULL,
		assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_rotated_at TIMESTAMP,
		next_rotation_at TIMESTAMP,
		PRIMARY KEY (secret_id, policy_id)
	);
	CREATE TABLE rotation_reminders (
		id TEXT PRIMARY KEY,
		secret_id TEXT NOT NULL,
		policy_id TEXT NOT NULL,
		reminder_type TEXT NOT NULL,
		sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		next_reminder_at TIMESTAMP,
		acknowledged BOOLEAN NOT NULL DEFAULT FALSE
	);
`

// rotationFixture wires the real repositories, the real cryptography service
// and a real database. Mocked crypto cannot prove a round trip, and a round
// trip is the whole point of these tests.
type rotationFixture struct {
	conn         *sql.DB
	crypto       secrets.CryptographyService
	rotationSvc  secrets.RotationServiceInterface
	secretSvc    secrets.SecretService
	schedulerSvc secrets.SchedulerServiceInterface
	versionRepo  repositories.SecretVersionRepositoryInterface
	userID       uuid.UUID
	vaultID      uuid.UUID
	secretID     uuid.UUID
	policyID     uuid.UUID
}

// scope returns the vault scope a CLI caller would use.
func (f *rotationFixture) scope() model.Scope {
	return model.NewVaultScope(f.vaultID, f.userID)
}

// newRotationFixture seeds one owner, one secret holding plaintext, and one
// auto-rotate policy already assigned to it with a next rotation in the past.
func newRotationFixture(t *testing.T, plaintext string) *rotationFixture {
	t.Helper()

	// The cryptography service reads master_key from the global viper
	// singleton, so these tests must not run in parallel.
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	previousKey := viper.GetString("master_key")
	viper.Set("master_key", base64.StdEncoding.EncodeToString(key))
	t.Cleanup(func() { viper.Set("master_key", previousKey) })

	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck,gosec

	_, err = conn.Exec(rotationFixtureSchema)
	require.NoError(t, err)

	log := testutils.NewTestLogger(t)
	dbConn := rvdb.NewConn(conn, rvdb.SQLite)

	secretRepo := repositories.NewSecretRepository(dbConn, log)
	rotationRepo := repositories.NewRotationPolicyRepository(dbConn, log)
	versionRepo := repositories.NewSecretVersionRepository(dbConn, log)
	userRepo := repositories.NewUserRepository(dbConn, log)
	tagRepo := repositories.NewSecretTagRepository(dbConn)

	crypto := secrets.NewCryptographyService()
	versioningSvc := secrets.NewVersioningService(versionRepo, secretRepo, userRepo, crypto, log, nil)
	rotationSvc := secrets.NewRotationService(rotationRepo, secretRepo, userRepo, crypto, versioningSvc, log, nil)
	secretSvc := secrets.NewSecretService(secrets.SecretServiceConfig{
		SecretRepository: secretRepo,
		CryptoService:    crypto,
		VersionService:   versioningSvc,
		TagService:       secrets.NewTagService(tagRepo, log),
		Logger:           log,
	})
	schedulerSvc := secrets.NewSchedulerService(rotationSvc, versioningSvc, userRepo, secretRepo, rotationRepo, log)

	f := &rotationFixture{
		conn:         conn,
		crypto:       crypto,
		rotationSvc:  rotationSvc,
		secretSvc:    secretSvc,
		schedulerSvc: schedulerSvc,
		versionRepo:  versionRepo,
		userID:       uuid.New(),
		vaultID:      uuid.New(),
		secretID:     uuid.New(),
		policyID:     uuid.New(),
	}

	now := time.Now()
	_, err = conn.Exec(
		`INSERT INTO users (id, username, password_hash, totp_secret, role, auth_provider, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		f.userID.String(), "alice", "hash", "", model.RoleUser, "local", now,
	)
	require.NoError(t, err)

	ciphertext, err := crypto.EncryptSecret(plaintext)
	require.NoError(t, err)
	_, err = conn.Exec(
		`INSERT INTO secrets (id, user_id, name, vault_id, value, version, created_at, content_type, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.secretID.String(), f.userID.String(), "db-password", f.vaultID.String(),
		ciphertext, 1, now, "", true,
	)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, rotationRepo.Create(ctx, &model.RotationPolicy{
		ID:           f.policyID,
		UserID:       f.userID,
		VaultID:      f.vaultID,
		Name:         "monthly",
		IntervalDays: 30,
		Enabled:      true,
		ReminderDays: 0,
		AutoRotate:   true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}))
	// The next rotation is backdated so the scheduler sees this pair as due.
	require.NoError(t, rotationRepo.AssignToSecret(ctx, f.secretID, f.policyID,
		now.AddDate(0, 0, -60), now.AddDate(0, 0, -30)))

	return f
}

// TestPerformManualRotation_ExplicitValue_RoundTripsThroughGetSecret is the
// test whose absence let B35 ship: nothing ever rotated a secret and then read
// it back.
func TestPerformManualRotation_ExplicitValue_RoundTripsThroughGetSecret(t *testing.T) {
	ctx := context.Background()
	f := newRotationFixture(t, "original-password")

	require.NoError(t, f.rotationSvc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: f.secretID,
		PolicyID: f.policyID,
		Scope:    f.scope(),
		Notes:    "manual rotation",
		NewValue: "replacement-password",
	}))

	got, err := f.secretSvc.GetSecret(ctx, f.secretID, f.scope())
	require.NoError(t, err, "a rotated secret must still decrypt")
	assert.Equal(t, "replacement-password", got.Value)
	assert.Equal(t, 2, got.Version)
}

// TestPerformManualRotation_ArchivesThePreviousValue pins the second half of
// B35: the manual path used to overwrite the old value with no version row, so
// the pre-rotation value was gone for good.
func TestPerformManualRotation_ArchivesThePreviousValue(t *testing.T) {
	ctx := context.Background()
	f := newRotationFixture(t, "original-password")

	require.NoError(t, f.rotationSvc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: f.secretID,
		PolicyID: f.policyID,
		Scope:    f.scope(),
		NewValue: "replacement-password",
	}))

	versions, err := f.versionRepo.GetVersions(ctx, f.secretID)
	require.NoError(t, err)
	require.Len(t, versions, 1, "manual rotation must archive exactly one version row")
	assert.Equal(t, 1, versions[0].Version)

	archived, err := f.crypto.DecryptSecret(versions[0].Value)
	require.NoError(t, err, "the archived version must be singly encrypted, not encrypted ciphertext")
	assert.Equal(t, "original-password", archived)
}

// TestPerformManualRotation_GeneratedValue_RoundTrips covers the opt-in
// generation path.
func TestPerformManualRotation_GeneratedValue_RoundTrips(t *testing.T) {
	ctx := context.Background()
	f := newRotationFixture(t, "original-password")

	require.NoError(t, f.rotationSvc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: f.secretID,
		PolicyID: f.policyID,
		Scope:    f.scope(),
		Generate: true,
		GenerateOpts: pwgen.Options{
			Length: 24, Upper: true, Lower: true, Numbers: true, Special: true,
		},
	}))

	got, err := f.secretSvc.GetSecret(ctx, f.secretID, f.scope())
	require.NoError(t, err)
	assert.Len(t, got.Value, 24, "the generated value must honour GenerateOpts.Length")
	assert.NotEqual(t, "original-password", got.Value)
	assert.NotContains(t, got.Value, "_rotated_", "the placeholder generator must be gone")
}

// TestPerformManualRotation_RequiresAValueSource pins the "never invent a
// value" rule.
func TestPerformManualRotation_RequiresAValueSource(t *testing.T) {
	ctx := context.Background()
	f := newRotationFixture(t, "original-password")

	err := f.rotationSvc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: f.secretID,
		PolicyID: f.policyID,
		Scope:    f.scope(),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrRotationValueRequired), "got %v", err)

	got, getErr := f.secretSvc.GetSecret(ctx, f.secretID, f.scope())
	require.NoError(t, getErr, "a rejected rotation must leave the secret untouched")
	assert.Equal(t, "original-password", got.Value)
	assert.Equal(t, 1, got.Version)
}

// TestPerformManualRotation_RejectsBothValueAndGenerate pins the ambiguous
// case: two value sources is a caller error, not a precedence rule.
func TestPerformManualRotation_RejectsBothValueAndGenerate(t *testing.T) {
	ctx := context.Background()
	f := newRotationFixture(t, "original-password")

	err := f.rotationSvc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: f.secretID,
		PolicyID: f.policyID,
		Scope:    f.scope(),
		NewValue: "replacement-password",
		Generate: true,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, secrets.ErrRotationValueConflict), "got %v", err)

	got, getErr := f.secretSvc.GetSecret(ctx, f.secretID, f.scope())
	require.NoError(t, getErr)
	assert.Equal(t, "original-password", got.Value)
}
```

- [ ] **Step 2: Run the test and watch it fail**

Run: `go test ./internal/services/secrets/ -run TestPerformManualRotation_ -v`
Expected: FAIL to build —
`unknown field NewValue in struct literal of type secrets.ManualRotationRequest`
and `undefined: secrets.ErrRotationValueRequired`.

- [ ] **Step 3: Add the value source to the request**

In `internal/services/secrets/rotation_service.go`, replace
`ManualRotationRequest` (l.79-85) with:

```go
// ManualRotationRequest represents the request to perform manual rotation.
//
// Exactly one value source must be set. Rotation never invents a value: with
// neither NewValue nor Generate it fails, because a generated string is wrong
// whenever the secret must match an external system, and silently keeping the
// old value would be a rotation that rotated nothing.
type ManualRotationRequest struct {
	SecretID uuid.UUID   `json:"secret_id" validate:"required"`
	PolicyID uuid.UUID   `json:"policy_id" validate:"required"`
	Scope    model.Scope // Authorization scope shared by both the secret and the policy read.
	Notes    string      `json:"notes" validate:"max=500"`
	// NewValue is the explicit replacement value, in plaintext.
	NewValue string `json:"new_value"`
	// Generate asks for a random replacement value instead of an explicit one.
	Generate bool `json:"generate"`
	// GenerateOpts tunes generation. A zero value means pwgen.DefaultOptions.
	GenerateOpts pwgen.Options `json:"generate_opts"`
}
```

Add the two sentinel errors just below it:

```go
// ErrRotationValueRequired is returned when a rotation request names no value
// source at all.
var ErrRotationValueRequired = errors.New("rotation requires a new value: set NewValue or Generate")

// ErrRotationValueConflict is returned when a rotation request names both
// value sources, which is ambiguous rather than a precedence question.
var ErrRotationValueConflict = errors.New("rotation cannot take both an explicit value and a generated one")
```

Extend the import block (l.6-16) to:

```go
import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/internal/pwgen"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)
```

- [ ] **Step 4: Add the value resolver**

Append to `internal/services/secrets/rotation_service.go`, replacing the
deleted `generateNewSecretValue` (see Step 6):

```go
// resolveRotationValue returns the plaintext a rotation should write. It is a
// pure function of the request, so it runs before any I/O and a bad request
// costs nothing.
func resolveRotationValue(req ManualRotationRequest) (string, error) {
	switch {
	case req.NewValue != "" && req.Generate:
		return "", ErrRotationValueConflict
	case req.NewValue != "":
		return req.NewValue, nil
	case req.Generate:
		opts := req.GenerateOpts
		if opts == (pwgen.Options{}) {
			opts = pwgen.DefaultOptions()
		}
		value, err := pwgen.Generate(opts)
		if err != nil {
			return "", fmt.Errorf("failed to generate a replacement value: %w", err)
		}
		return value, nil
	default:
		return "", ErrRotationValueRequired
	}
}
```

- [ ] **Step 5: Rewrite `PerformManualRotation`**

Replace `internal/services/secrets/rotation_service.go` l.359-436 with:

```go
// PerformManualRotation performs manual rotation with full business logic.
//
// It writes the secrets table directly rather than through the secret service,
// so it owns both its audit trail and its cache invalidation. The secret and
// policy are both read under req.Scope, the same structural cross-vault
// guard AssignPolicyToSecret uses.
//
// The order is deliberate: resolve the replacement value, archive the value
// being replaced, encrypt, then write. Archiving is fatal on failure -- a
// rotation that cannot preserve the old value must not destroy it.
func (s *rotationService) PerformManualRotation(ctx context.Context, req ManualRotationRequest) error {
	actor := req.Scope.ActorID().String()

	newPlaintext, err := resolveRotationValue(req)
	if err != nil {
		s.log.LogAuditError(actor, "rotate_secret", "failed", "No usable replacement value in the request", err)
		return err
	}

	secret, err := s.secretRepo.Read(ctx, req.SecretID, req.Scope)
	if err != nil {
		s.log.LogAuditError(actor, "rotate_secret", "failed", "Secret not found", err)
		return fmt.Errorf("secret not found: %w", err)
	}

	policy, err := s.rotationRepo.Read(ctx, req.PolicyID, req.Scope)
	if err != nil {
		s.log.LogAuditError(actor, "rotate_secret", "failed", "Rotation policy not found", err)
		return fmt.Errorf("policy not found: %w", err)
	}

	// The stored value is ciphertext and CreateVersion encrypts whatever it is
	// given, so the plaintext is what must be archived -- exactly as
	// SecretService.UpdateSecret does. Passing the ciphertext straight through
	// would store it doubly encrypted.
	currentPlaintext, err := s.cryptoSvc.DecryptSecret(secret.Value)
	if err != nil {
		s.log.LogAuditError(actor, "rotate_secret", "failed", "Failed to decrypt the current value", err)
		return fmt.Errorf("failed to decrypt the current secret value: %w", err)
	}

	// CreateVersion gates on secret.UserID == req.UserID, so pass the secret's
	// real owner here, never the scope's actor: a legitimate vault-scoped
	// rotation by a non-owner member must not be rejected by that gate.
	if _, err = s.versioningSvc.CreateVersion(ctx, CreateVersionRequest{
		SecretID: secret.ID,
		UserID:   secret.UserID,
		Name:     secret.Name,
		Value:    currentPlaintext,
		Version:  secret.Version,
	}); err != nil {
		s.log.LogAuditError(actor, "rotate_secret", "failed", "Failed to archive the pre-rotation value", err)
		return fmt.Errorf("failed to archive the pre-rotation value: %w", err)
	}

	encryptedValue, err := s.cryptoSvc.EncryptSecret(newPlaintext)
	if err != nil {
		s.log.LogAuditError(actor, "rotate_secret", "failed", "Failed to encrypt the replacement value", err)
		return fmt.Errorf("failed to encrypt the replacement value: %w", err)
	}

	// Update secret with new value and incremented version
	previousVersion := secret.Version
	secret.Value = encryptedValue
	secret.Version++

	err = s.secretRepo.Update(ctx, secret, model.NewOwnerScope(secret.VaultID, secret.UserID))
	if err != nil {
		s.log.WithError(err).Error("Failed to update secret during rotation")
		s.log.LogAuditError(actor, "rotate_secret", "failed", "Failed to update secret during rotation", err)
		return fmt.Errorf("failed to update secret during rotation: %w", err)
	}

	// The write bypassed CachedSecretService. Without this eviction a
	// credential rotated because it was compromised would keep being served
	// from cache for the full TTL after rotation reported success.
	s.invalidateCache(ctx, req.SecretID)

	// Record rotation history
	now := time.Now()
	history := &model.RotationHistory{
		ID:              uuid.New(),
		SecretID:        req.SecretID,
		PolicyID:        &req.PolicyID,
		RotatedAt:       now,
		PreviousVersion: previousVersion,
		NewVersion:      secret.Version,
		TriggeredBy:     model.TriggerManual,
		Notes:           req.Notes,
	}

	if err := s.rotationRepo.RecordRotation(ctx, history); err != nil {
		s.log.WithError(err).Error("Failed to record rotation history")
		// Don't fail rotation if history recording fails
	}

	// Update next rotation time
	nextRotation := now.AddDate(0, 0, policy.IntervalDays)
	if err := s.rotationRepo.UpdateSecretPolicyRotation(ctx, req.SecretID, req.PolicyID, now, nextRotation); err != nil {
		s.log.WithError(err).Error("Failed to update next rotation time")
		// Don't fail rotation if scheduling update fails
	}

	s.log.LogAuditInfo(actor, "rotate_secret", "success",
		fmt.Sprintf("Secret %s rotated to version %d", req.SecretID, secret.Version))

	s.log.WithFields(map[string]interface{}{
		"secret_id":   req.SecretID,
		"policy_id":   req.PolicyID,
		"actor":       actor,
		"new_version": secret.Version,
	}).Info("Manual rotation completed successfully")

	return nil
}
```

- [ ] **Step 6: Delete the placeholder generator**

Delete `internal/services/secrets/rotation_service.go` l.539-545 entirely:

```go
// generateNewSecretValue generates a new value for a secret (simplified implementation).
// In production, this would be more sophisticated based on secret type.
func (s *rotationService) generateNewSecretValue(currentValue string) string {
	// This is a simplified implementation
	// In production, you'd want more sophisticated generation based on secret type
	return fmt.Sprintf("%s_rotated_%d", currentValue, time.Now().Unix())
}
```

- [ ] **Step 7: Run the new tests and watch them pass**

Run: `go test ./internal/services/secrets/ -run TestPerformManualRotation_ -v`
Expected: PASS — five tests, including
`TestPerformManualRotation_ExplicitValue_RoundTripsThroughGetSecret`.

- [ ] **Step 8: Confirm the legacy tests now fail, and see why**

Run: `go test ./internal/services/secrets/ 2>&1 | head -30`
Expected: FAIL. `TestPerformManualRotationInvalidatesCacheAndAudits`,
`TestDirectWritersToleratesANoOpCacheInvalidator` and the two
`coverage_boost_test.go` rotation cases pass a request with no value source, so
they now get `ErrRotationValueRequired`. They encode the corrupt behavior and
must be updated, not worked around.

- [ ] **Step 9: Update `TestPerformManualRotationInvalidatesCacheAndAudits`**

In `internal/services/secrets/direct_write_invalidation_test.go`, replace the
body of the test at l.89-127 with:

```go
func TestPerformManualRotationInvalidatesCacheAndAudits(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ownerID := uuid.New()
	secretID := uuid.New()
	policyID := uuid.New()

	scope := model.NewAdminScope(ownerID)

	secretRepo := &testutils.MockSecretRepository{}
	secretRepo.On("Read", ctx, secretID, scope).
		Return(&model.Secret{ID: secretID, UserID: ownerID, Name: "db", Value: "old-ciphertext", Version: 3}, nil).Once()
	secretRepo.On("Update", ctx, mock.Anything, mock.Anything).Return(nil).Once()

	rotationRepo := &mockRotationPolicyRepo{}
	rotationRepo.On("Read", ctx, policyID, scope).
		Return(&model.RotationPolicy{ID: policyID, UserID: ownerID, IntervalDays: 30}, nil).Once()
	rotationRepo.On("RecordRotation", ctx, mock.Anything).Return(nil).Once()
	rotationRepo.On("UpdateSecretPolicyRotation", ctx, secretID, policyID, mock.Anything, mock.Anything).
		Return(nil).Once()

	crypto := &testutils.MockCryptographyService{}
	crypto.On("DecryptSecret", "old-ciphertext").Return("old-plaintext", nil).Once()
	crypto.On("EncryptSecret", "new-plaintext").Return("new-ciphertext", nil).Once()

	versioningSvc := &testutils.MockVersioningService{}
	versioningSvc.On("CreateVersion", ctx, mock.MatchedBy(func(req secrets.CreateVersionRequest) bool {
		return req.SecretID == secretID && req.UserID == ownerID &&
			req.Value == "old-plaintext" && req.Version == 3
	})).Return(&model.SecretVersion{ID: uuid.New()}, nil).Once()

	invalidator := &recordingInvalidator{}
	logger, audit := newAuditingLogger(t)
	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, crypto, versioningSvc, logger, invalidator)

	require.NoError(t, svc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: secretID,
		PolicyID: policyID,
		Scope:    scope,
		NewValue: "new-plaintext",
	}))

	assert.Equal(t, []uuid.UUID{secretID}, invalidator.ids(), "rotation must evict the rotated secret from cache")

	rec, ok := audit.find("rotate_secret", "success")
	require.True(t, ok, "rotation must emit a success audit row")
	assert.Equal(t, ownerID.String(), rec.userID, "the audit actor is the secret's owner, never uuid.Nil")

	secretRepo.AssertExpectations(t)
	rotationRepo.AssertExpectations(t)
	crypto.AssertExpectations(t)
	versioningSvc.AssertExpectations(t)
}
```

- [ ] **Step 10: Update `TestDirectWritersToleratesANoOpCacheInvalidator`**

In the same file, replace the body at l.213-250 with:

```go
func TestDirectWritersToleratesANoOpCacheInvalidator(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ownerID := uuid.New()
	secretID := uuid.New()
	policyID := uuid.New()

	scope := model.NewAdminScope(ownerID)

	secretRepo := &testutils.MockSecretRepository{}
	secretRepo.On("Read", ctx, secretID, scope).
		Return(&model.Secret{ID: secretID, UserID: ownerID, Name: "db", Value: "old-ciphertext", Version: 1}, nil).Once()
	secretRepo.On("Update", ctx, mock.Anything, mock.Anything).Return(nil).Once()

	rotationRepo := &mockRotationPolicyRepo{}
	rotationRepo.On("Read", ctx, policyID, scope).
		Return(&model.RotationPolicy{ID: policyID, UserID: ownerID, IntervalDays: 7}, nil).Once()
	rotationRepo.On("RecordRotation", ctx, mock.Anything).Return(nil).Once()
	rotationRepo.On("UpdateSecretPolicyRotation", ctx, secretID, policyID, mock.Anything, mock.Anything).
		Return(nil).Once()

	crypto := &testutils.MockCryptographyService{}
	crypto.On("DecryptSecret", "old-ciphertext").Return("old-plaintext", nil).Once()
	crypto.On("EncryptSecret", "new-plaintext").Return("new-ciphertext", nil).Once()

	versioningSvc := &testutils.MockVersioningService{}
	versioningSvc.On("CreateVersion", ctx, mock.Anything).Return(&model.SecretVersion{ID: uuid.New()}, nil).Once()

	logger, _ := newAuditingLogger(t)
	invalidator := &recordingInvalidator{}
	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, crypto, versioningSvc, logger, invalidator)

	require.NoError(t, svc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: secretID,
		PolicyID: policyID,
		Scope:    scope,
		NewValue: "new-plaintext",
	}))
}
```

- [ ] **Step 11: Update the `coverage_boost_test.go` rotation cases**

In `internal/services/secrets/coverage_boost_test.go`, the service at l.976 is
built with `crypto := &testutils.MockCryptographyService{}` and `nil` for
versioning. Change that construction (as edited in Task 2, Step 5) to:

```go
	versionSvc := &testutils.MockVersioningService{}
	svc := secrets.NewRotationService(repo, secretRepo, userRepo, crypto, versionSvc, testutils.NewTestLogger(t), &recordingInvalidator{})
```

Then replace the rotation block at l.1004-1019 with:

```go
	secretRepo.On("Read", ctx, secretID, scope).Return(secret, nil).Once()
	repo.On("Read", ctx, policyID, scope).Return(policy, nil).Once()
	crypto.On("DecryptSecret", "current").Return("current-plaintext", nil).Once()
	crypto.On("EncryptSecret", "next-plaintext").Return("next-ciphertext", nil).Once()
	versionSvc.On("CreateVersion", ctx, mock.MatchedBy(func(req secrets.CreateVersionRequest) bool {
		return req.SecretID == secretID && req.Value == "current-plaintext" && req.Version == 3
	})).Return(&model.SecretVersion{ID: uuid.New()}, nil).Once()
	secretRepo.On("Update", ctx, mock.MatchedBy(func(updated *model.Secret) bool {
		return updated.ID == secretID && updated.Version == 4 && updated.Value == "next-ciphertext"
	}), model.NewOwnerScope(secret.VaultID, secret.UserID)).Return(nil).Once()
	repo.On("RecordRotation", ctx, mock.MatchedBy(func(history *model.RotationHistory) bool {
		return history.SecretID == secretID && *history.PolicyID == policyID && history.PreviousVersion == 3 && history.NewVersion == 4
	})).Return(nil).Once()
	repo.On("UpdateSecretPolicyRotation", ctx, secretID, policyID, mock.AnythingOfType("time.Time"), mock.AnythingOfType("time.Time")).Return(nil).Once()

	require.NoError(t, svc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: secretID,
		PolicyID: policyID,
		Scope:    scope,
		Notes:    "rotate now",
		NewValue: "next-plaintext",
	}))
```

Add `versionSvc.AssertExpectations(t)` next to the existing
`secretRepo.AssertExpectations(t)` at the end of that test.

In the error-branch test, the service at l.1076 keeps `nil` versioning for the
cases that fail before archiving; change the construction to:

```go
	versionSvc := &testutils.MockVersioningService{}
	svc := secrets.NewRotationService(repo, secretRepo, userRepo, crypto, versionSvc, testutils.NewTestLogger(t), nil)
```

and replace the two rotation error cases at l.1142-1151 with:

```go
	secretRepo.On("Read", ctx, secretID, scope).Return(nil, errors.New("missing secret")).Once()
	err = svc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: secretID, PolicyID: policyID, Scope: scope, NewValue: "next-plaintext",
	})
	assert.ErrorContains(t, err, "secret not found")

	// A request with no value source fails before any repository call.
	err = svc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: secretID, PolicyID: policyID, Scope: scope,
	})
	assert.ErrorIs(t, err, secrets.ErrRotationValueRequired)

	secretRepo.On("Read", ctx, secretID, scope).Return(secret, nil).Once()
	repo.On("Read", ctx, policyID, scope).Return(policy, nil).Once()
	crypto.On("DecryptSecret", "current").Return("current-plaintext", nil).Once()
	crypto.On("EncryptSecret", "next-plaintext").Return("next-ciphertext", nil).Once()
	versionSvc.On("CreateVersion", ctx, mock.Anything).Return(&model.SecretVersion{ID: uuid.New()}, nil).Once()
	secretRepo.On("Update", ctx, mock.AnythingOfType("*model.Secret"), model.NewOwnerScope(secret.VaultID, secret.UserID)).Return(errors.New("update failed")).Once()
	err = svc.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: secretID, PolicyID: policyID, Scope: scope, NewValue: "next-plaintext",
	})
	assert.ErrorContains(t, err, "failed to update secret during rotation")
```

- [ ] **Step 12: Run the whole package**

Run:
```bash
go build ./...
go test ./internal/services/secrets/
gofmt -l internal/services/secrets
go vet ./internal/services/secrets/
```
Expected: all pass, `gofmt` silent. If the scheduler test in
`coverage_boost_test.go` (l.1231-1244) still passes here, that is expected —
Task 4 changes it.

- [ ] **Step 13: Commit**

```bash
git add internal/services/secrets/rotation_service.go internal/services/secrets/rotation_roundtrip_test.go internal/services/secrets/direct_write_invalidation_test.go internal/services/secrets/coverage_boost_test.go
git commit -m "fix(rotation): stop writing a corrupted value on rotation (B35)

PerformManualRotation appended '_rotated_<unix>' to the stored master-key
ciphertext and wrote it back unencrypted, so a rotated secret could never
be decrypted again. It now takes the replacement value from the caller or
generates one on request, archives the pre-rotation value through the
versioning service, and encrypts through the CryptographyService that was
already injected and never called."
```

---

### Task 4: Scheduler generates its value and stops double-versioning

**Files:**
- Modify: `internal/services/secrets/scheduler_service.go` (`ManualSchedulerRotationRequest` l.33-39, `PerformManualRotation` l.170-197, `performAutomaticRotation` l.199-259)
- Modify: `internal/services/secrets/rotation_roundtrip_test.go` (add the scheduler test)
- Modify: `internal/services/secrets/coverage_boost_test.go` (scheduler expectations at l.1229-1250)

**Interfaces:**
- Consumes: `ManualRotationRequest{NewValue, Generate, GenerateOpts}` from Task 3,
  `pwgen.DefaultOptions()`.
- Produces:
  ```go
  type ManualSchedulerRotationRequest struct {
      SecretID     uuid.UUID
      PolicyID     uuid.UUID
      UserID       uuid.UUID
      Notes        string
      NewValue     string
      Generate     bool
      GenerateOpts pwgen.Options
  }
  ```

Unattended rotation has no operator to supply a value, so the automatic path
generates one — the one place where generation is the only option. The
scheduler's own `CreateVersion` call goes away because
`PerformManualRotation` now versions on every path; leaving it would write two
version rows per rotation, and the scheduler's copy passes ciphertext to a
function that encrypts, so its rows are doubly encrypted.

- [ ] **Step 1: Write the failing scheduler test**

Append to `internal/services/secrets/rotation_roundtrip_test.go`:

```go
// TestScheduler_AutomaticRotation_RoundTripsAndVersionsOnce covers the path
// that made B35 Critical: a policy with AutoRotate corrupts its secret on a
// timer, unattended. It also pins the single version row -- the scheduler used
// to write its own, on top of the one rotation now writes.
func TestScheduler_AutomaticRotation_RoundTripsAndVersionsOnce(t *testing.T) {
	ctx := context.Background()
	f := newRotationFixture(t, "original-password")

	require.NoError(t, f.schedulerSvc.ProcessUserRotations(ctx, f.userID))

	got, err := f.secretSvc.GetSecret(ctx, f.secretID, f.scope())
	require.NoError(t, err, "an automatically rotated secret must still decrypt")
	assert.NotEqual(t, "original-password", got.Value)
	assert.NotContains(t, got.Value, "_rotated_")
	assert.Equal(t, 2, got.Version)

	versions, err := f.versionRepo.GetVersions(ctx, f.secretID)
	require.NoError(t, err)
	require.Len(t, versions, 1, "automatic rotation must write exactly one version row")

	archived, err := f.crypto.DecryptSecret(versions[0].Value)
	require.NoError(t, err, "the archived version must be singly encrypted")
	assert.Equal(t, "original-password", archived)
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `go test ./internal/services/secrets/ -run TestScheduler_AutomaticRotation -v`
Expected: FAIL — the rotation errors with
`rotation requires a new value: set NewValue or Generate`, which
`ProcessUserRotations` logs rather than returns, so the assertion that fails
first is `assert.NotEqual(t, "original-password", got.Value)` (the secret was
never rotated), and `require.Len(t, versions, 1)` finds one *doubly encrypted*
row from the scheduler's own `CreateVersion`.

- [ ] **Step 3: Add the value source to the scheduler's manual request**

In `internal/services/secrets/scheduler_service.go`, replace l.33-39 with:

```go
// ManualSchedulerRotationRequest represents a manual rotation request through
// the scheduler. Its value source is passed straight through to
// ManualRotationRequest, so the same "never invent a value" rule applies.
type ManualSchedulerRotationRequest struct {
	SecretID     uuid.UUID     `json:"secret_id" validate:"required"`
	PolicyID     uuid.UUID     `json:"policy_id" validate:"required"`
	UserID       uuid.UUID     `json:"user_id" validate:"required"`
	Notes        string        `json:"notes" validate:"max=500"`
	NewValue     string        `json:"new_value"`
	Generate     bool          `json:"generate"`
	GenerateOpts pwgen.Options `json:"generate_opts"`
}
```

and add `"rocketvault/internal/pwgen"` to the import block (l.6-17), between
`"rocketvault/internal/logging"` and `"rocketvault/internal/repositories"`.

- [ ] **Step 4: Pass the value source through the manual path**

Replace the request literal in `schedulerService.PerformManualRotation`
(l.173-178) with:

```go
	rotationReq := ManualRotationRequest{
		SecretID:     req.SecretID,
		PolicyID:     req.PolicyID,
		Scope:        model.NewAdminScope(req.UserID),
		Notes:        req.Notes,
		NewValue:     req.NewValue,
		Generate:     req.Generate,
		GenerateOpts: req.GenerateOpts,
	}
```

- [ ] **Step 5: Generate in the automatic path and drop the duplicate version**

In `performAutomaticRotation`, delete l.224-237 entirely:

```go
	// Create version before rotation
	versionReq := CreateVersionRequest{
		SecretID: sp.SecretID,
		UserID:   secret.UserID,
		Name:     secret.Name,
		Value:    secret.Value,
		Version:  secret.Version + 1,
	}

	_, err = s.versioningSvc.CreateVersion(ctx, versionReq)
	if err != nil {
		s.log.WithError(err).Error("Failed to create version before automatic rotation")
		// Continue with rotation even if versioning fails
	}
```

and replace the request literal at l.240-245 with:

```go
	// Perform automatic rotation using rotation service. Unattended rotation
	// has no operator to supply a value, so this is the one path where
	// generating one is the only option. Versioning is not repeated here:
	// PerformManualRotation archives the pre-rotation value itself, and a
	// second CreateVersion would write a duplicate row.
	rotationReq := ManualRotationRequest{
		SecretID:     sp.SecretID,
		PolicyID:     sp.PolicyID,
		Scope:        model.NewAdminScope(secret.UserID),
		Notes:        "Automatic rotation by scheduler",
		Generate:     true,
		GenerateOpts: pwgen.DefaultOptions(),
	}
```

The `versioningSvc` field stays on `schedulerService`: it is part of the
constructor's contract and the container always supplies it. Leave the struct
and `NewSchedulerService` untouched.

- [ ] **Step 6: Run the scheduler test and watch it pass**

Run: `go test ./internal/services/secrets/ -run TestScheduler_AutomaticRotation -v`
Expected: PASS.

- [ ] **Step 7: Update the mocked scheduler expectations**

Run: `go test ./internal/services/secrets/ 2>&1 | head -20`
Expected: FAIL in `coverage_boost_test.go` — the mocked
`PerformManualRotation` expectation no longer matches, and the
`versionSvc.CreateVersion` expectation is never met.

In `internal/services/secrets/coverage_boost_test.go`, delete the
`versionSvc.On("CreateVersion", ...)` expectation at l.1235-1237 and replace
the rotation expectation at l.1238-1243 with:

```go
	rotationSvc.On("PerformManualRotation", ctx, secrets.ManualRotationRequest{
		SecretID:     secretID,
		PolicyID:     policyID,
		Scope:        model.NewAdminScope(userID),
		Notes:        "Automatic rotation by scheduler",
		Generate:     true,
		GenerateOpts: pwgen.DefaultOptions(),
	}).Return(nil).Once()
```

Add `"rocketvault/internal/pwgen"` to that file's imports.

Then update the manual-through-scheduler expectation at l.1245-1250 so it
carries a value source:

```go
	manualReq := secrets.ManualSchedulerRotationRequest{
		SecretID: secretID, PolicyID: policyID, UserID: userID, Notes: "manual",
		NewValue: "operator-supplied",
	}
	rotationSvc.On("PerformManualRotation", ctx, secrets.ManualRotationRequest{
		SecretID: secretID,
		PolicyID: policyID,
		Scope:    model.NewAdminScope(userID),
		Notes:    "manual",
		NewValue: "operator-supplied",
	}).Return(nil).Once()
	require.NoError(t, svc.PerformManualRotation(ctx, manualReq))
```

- [ ] **Step 8: Run the package**

Run:
```bash
go build ./...
go test ./internal/services/secrets/
gofmt -l internal/services/secrets
go vet ./internal/services/secrets/
```
Expected: all pass, `gofmt` silent.

- [ ] **Step 9: Commit**

```bash
git add internal/services/secrets/scheduler_service.go internal/services/secrets/rotation_roundtrip_test.go internal/services/secrets/coverage_boost_test.go
git commit -m "fix(rotation): scheduler generates a real value and versions once

Automatic rotation now asks the rotation service to generate a value
instead of relying on the deleted placeholder, and drops its own
CreateVersion call: rotation archives the pre-rotation value itself, so
the scheduler's copy only produced a second, doubly encrypted row."
```

---

### Task 5: `--value` and `--generate` on `secrets rotation rotate`

**Files:**
- Modify: `cmd/rotation.go` (flag vars l.39-47, `rotationRotateCmd` l.276-306, flag registration l.396-400, `runRotationRotate` l.622-654)
- Modify: `cmd/rotation_service_test.go` (l.168-188)
- Modify: `cmd/cmd_test.go` (l.1207-1226)

**Interfaces:**
- Consumes: `secrets.ManualRotationRequest{NewValue, Generate, GenerateOpts}`,
  `pwgen.Options`.
- Produces: no exported Go API; the CLI surface
  `rocketvault secrets rotation rotate --value | --generate [--length N]
  [--uppercase] [--lowercase] [--numbers] [--special]`.

The flag values are held in package-level variables rather than read through
`cmd.Flags()`, matching `secretID`/`policyID` in this file. Several tests build
a bare `&cobra.Command{RunE: rotationRotateCmd.RunE}` with no flags
registered, so a `cmd.Flags().GetString` call would return the zero value and
an ignored error instead of the caller's intent.

- [ ] **Step 1: Write the failing CLI tests**

Append to `cmd/rotation_service_test.go`:

```go
// TestRotationRotate_NeitherValueNorGenerate_IsAnError pins the CLI half of
// B35's "never invent a value" rule: the error must name both ways out.
func TestRotationRotate_NeitherValueNorGenerate_IsAnError(t *testing.T) {
	tc, _ := setupRotationTestContext(t)

	secretID = uuid.New().String()
	policyID = uuid.New().String()
	rotateValue = ""
	rotateGenerate = false

	cmd := &cobra.Command{Use: "rotate", RunE: rotationRotateCmd.RunE}
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--value")
	assert.Contains(t, err.Error(), "--generate")
}

// TestRotationRotate_BothValueAndGenerate_IsAnError keeps the two sources
// mutually exclusive at the CLI, not just in the service.
func TestRotationRotate_BothValueAndGenerate_IsAnError(t *testing.T) {
	tc, _ := setupRotationTestContext(t)

	secretID = uuid.New().String()
	policyID = uuid.New().String()
	rotateValue = "explicit"
	rotateGenerate = true
	t.Cleanup(func() { rotateValue = ""; rotateGenerate = false })

	cmd := &cobra.Command{Use: "rotate", RunE: rotationRotateCmd.RunE}
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--value")
	assert.Contains(t, err.Error(), "--generate")
}

// TestRotationRotate_GenerateFlagsReachTheService proves the character-set
// flags are not decorative.
func TestRotationRotate_GenerateFlagsReachTheService(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	sid := uuid.New()
	pid := uuid.New()

	mockRotSvc.On("PerformManualRotation", mock.Anything, mock.MatchedBy(func(r secretServices.ManualRotationRequest) bool {
		return r.SecretID == sid && r.PolicyID == pid && r.NewValue == "" && r.Generate &&
			r.GenerateOpts == (pwgen.Options{Length: 32, Upper: true, Lower: true, Numbers: true, Special: false})
	})).Return(nil)

	secretID = sid.String()
	policyID = pid.String()
	rotateValue = ""
	rotateGenerate = true
	rotateLength = 32
	rotateUpper, rotateLower, rotateNumbers, rotateSpecial = true, true, true, false
	t.Cleanup(func() { rotateGenerate = false; rotateLength = 16; rotateSpecial = true })

	cmd := &cobra.Command{Use: "rotate", RunE: rotationRotateCmd.RunE}
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	mockRotSvc.AssertExpectations(t)
}
```

Add `"rocketvault/internal/pwgen"` and `"github.com/stretchr/testify/require"`
to that file's imports.

- [ ] **Step 2: Run and watch it fail**

Run: `go test ./cmd/ -run TestRotationRotate_ -v`
Expected: FAIL to build — `undefined: rotateValue`, `undefined: rotateGenerate`,
`undefined: rotateLength`.

- [ ] **Step 3: Add the flag variables and registration**

In `cmd/rotation.go`, extend the var block at l.39-47 to:

```go
var (
	policyName        string
	policyDescription string
	policyInterval    int
	policyReminder    int
	policyAutoRotate  bool
	policyID          string
	secretID          string

	// Rotate-only flags. They are package-level, like secretID and policyID
	// above, so that RunE reads them directly rather than through a flag set
	// the command's tests do not build.
	rotateValue    string
	rotateGenerate bool
	rotateLength   int
	rotateUpper    bool
	rotateLower    bool
	rotateNumbers  bool
	rotateSpecial  bool
)
```

and the rotate registration at l.396-400 to:

```go
	// Rotate command flags
	rotationRotateCmd.Flags().StringVar(&secretID, "secret-id", "", "Secret ID (required)")
	rotationRotateCmd.Flags().StringVar(&policyID, "policy-id", "", "Policy ID (required)")
	rotationRotateCmd.Flags().StringVar(&rotateValue, "value", "", "New secret value (mutually exclusive with --generate)")
	rotationRotateCmd.Flags().BoolVar(&rotateGenerate, "generate", false, "Generate a random new value instead of supplying one")
	rotationRotateCmd.Flags().IntVar(&rotateLength, "length", 16, "Length of the generated value (with --generate)")
	rotationRotateCmd.Flags().BoolVar(&rotateUpper, "uppercase", true, "Include uppercase letters in the generated value")
	rotationRotateCmd.Flags().BoolVar(&rotateLower, "lowercase", true, "Include lowercase letters in the generated value")
	rotationRotateCmd.Flags().BoolVar(&rotateNumbers, "numbers", true, "Include numbers in the generated value")
	rotationRotateCmd.Flags().BoolVar(&rotateSpecial, "special", true, "Include special characters in the generated value")
	rotationRotateCmd.MarkFlagRequired("secret-id") //nolint:errcheck,gosec
	rotationRotateCmd.MarkFlagRequired("policy-id") //nolint:errcheck,gosec
```

Add `"rocketvault/internal/pwgen"` to the imports (l.25-37), after
`"rocketvault/internal/container"`.

- [ ] **Step 4: Wire the flags into `runRotationRotate`**

Replace `cmd/rotation.go` l.645-653 (the service call and its success print)
with:

```go
	if rotateValue == "" && !rotateGenerate {
		return fmt.Errorf("no new value: pass --value <value> to set one, or --generate to have one generated")
	}
	if rotateValue != "" && rotateGenerate {
		return fmt.Errorf("--value and --generate are mutually exclusive; pass only one")
	}

	if err := sc.GetRotationService().PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: sid,
		PolicyID: pid,
		Scope:    scope,
		NewValue: rotateValue,
		Generate: rotateGenerate,
		GenerateOpts: pwgen.Options{
			Length:  rotateLength,
			Upper:   rotateUpper,
			Lower:   rotateLower,
			Numbers: rotateNumbers,
			Special: rotateSpecial,
		},
	}); err != nil {
		return fmt.Errorf("failed to rotate secret: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Secret rotated successfully.") //nolint:errcheck
	return nil
```

The two checks sit after the UUID parses on purpose, so the existing
`invalid secret ID` / `invalid policy ID` tests keep reporting the error they
assert on.

- [ ] **Step 5: Replace the help text that documented the bug**

The current `Long` describes the placeholder generator and warns the reader
off the command. Replace `rotationRotateCmd`'s `Long` and `Example`
(l.280-302) with:

```go
	Long: `Rotate one secret now, without waiting for its schedule. The secret's value
is replaced, the previous value is archived as a version, the version number
is incremented, a "manual" entry is added to its rotation history, and its
next rotation is pushed out by the policy's interval.

Requires the Microsoft.KeyVault/vaults/secrets/setSecret/action data action
in the vault named by --vault, which defaults to "default". No global role is
checked. The secret and the policy are both read in that vault.

The new value comes from you: pass --value to set one, or --generate to have
a random one generated with --length and the --uppercase/--lowercase/--numbers/--special
sets, exactly as "secrets generate-password" builds them. Passing neither is
an error, and passing both is rejected. Nothing outside RocketVault is
updated, so a rotated credential must still be changed in the system that
uses it.`,
	Example: `  # Rotate a secret to a value you supply
  rocketvault secrets rotation rotate --secret-id <secret-id> \
    --policy-id <policy-id> --value <new-value>

  # Rotate to a generated 32-character value with no special characters
  rocketvault secrets rotation rotate --secret-id <secret-id> \
    --policy-id <policy-id> --generate --length 32 --special=false

  # Rotate a secret in a named vault
  rocketvault secrets rotation rotate --secret-id <secret-id> \
    --policy-id <policy-id> --generate --vault payments`,
```

- [ ] **Step 6: Run the new CLI tests**

Run: `go test ./cmd/ -run TestRotationRotate_ -v`
Expected: PASS, three tests.

- [ ] **Step 7: Fix the two existing rotate tests**

Run: `go test ./cmd/ 2>&1 | head -20`
Expected: FAIL — `TestRotationRotateCommand_UsesContextContainer` and
`TestRunRotationRotate_ServiceReturnsError` now hit the "no new value" error
because they set no value source.

In `cmd/rotation_service_test.go`, add to
`TestRotationRotateCommand_UsesContextContainer` (after `policyID = pid.String()`):

```go
	rotateValue = "operator-supplied"
	rotateGenerate = false
	t.Cleanup(func() { rotateValue = "" })
```

and tighten its matcher to prove the value reaches the service:

```go
	mockRotSvc.On("PerformManualRotation", mock.Anything, mock.MatchedBy(func(r secretServices.ManualRotationRequest) bool {
		return r.SecretID == sid && r.PolicyID == pid &&
			r.Scope == model.NewVaultScope(tc.TestVaultID, tc.TestUserID) &&
			r.NewValue == "operator-supplied" && !r.Generate
	})).Return(nil)
```

In `cmd/cmd_test.go`, add to `TestRunRotationRotate_ServiceReturnsError`
(after `policyID = pid.String()`):

```go
	rotateValue = "operator-supplied"
	rotateGenerate = false
	t.Cleanup(func() { rotateValue = "" })
```

- [ ] **Step 8: Verify the help-text guard**

Run: `go test ./cmd/ -run 'TestExample|TestHelp' -v`
Expected: PASS — every flag named in the new `Example` block
(`--secret-id`, `--policy-id`, `--value`, `--generate`, `--length`,
`--special`, `--vault`) is registered on `rotationRotateCmd` or inherited from
`rotationCmd`.

- [ ] **Step 9: Run the whole cmd package**

Run:
```bash
go build ./...
go test ./cmd/...
gofmt -l cmd
go vet ./cmd/...
```
Expected: all pass, `gofmt` silent.

- [ ] **Step 10: Commit**

```bash
git add cmd/rotation.go cmd/rotation_service_test.go cmd/cmd_test.go
git commit -m "feat(cli): give secrets rotation rotate a real value source

Adds --value and --generate (with --length and the character-set flags,
mirroring secrets generate-password). Passing neither is an error naming
both options. The help text no longer documents the placeholder generator
that B35 removed."
```

---

### Task 6: Full verification and close out B35

**Files:**
- Modify: `.claude/known-bugs.md` (B35 entry, l.1748-1795)

**Interfaces:**
- Consumes: nothing.
- Produces: nothing.

- [ ] **Step 1: Full build, test, lint**

Run:
```bash
go build ./...
go test ./...
gofmt -l .
go vet ./...
```
Expected: all pass, `gofmt` silent. Nothing outside
`internal/services/secrets`, `internal/container` and `cmd` should have
changed.

- [ ] **Step 2: Prove it by hand against a scratch instance**

Per the house pattern for manual passes, use an isolated config and database
rather than `dev-rocketvault.db`:

```bash
go run . --config ./scratch-config.yaml secrets create --name rotate-me --value before-rotation
go run . --config ./scratch-config.yaml secrets rotation create --name quick --interval 1
go run . --config ./scratch-config.yaml secrets rotation assign --policy-id <id> --secret-id <id>
go run . --config ./scratch-config.yaml secrets rotation rotate --secret-id <id> --policy-id <id> --value after-rotation
go run . --config ./scratch-config.yaml secrets get --name rotate-me
go run . --config ./scratch-config.yaml secrets versions list --name rotate-me
```
Expected: `secrets get` prints `after-rotation`, not a decryption failure; the
versions listing shows a version 1 row. Also run the command with no `--value`
and no `--generate` and confirm the error names both flags.

- [ ] **Step 3: Mark B35 fixed**

In `.claude/known-bugs.md`, change the B35 Status/Severity block (as rewritten
in Task 1) to:

```
**Status**: Fixed 2026-08-21
**Severity**: Resolved — was Critical (re-rated from High during design:
`schedulerService.performAutomaticRotation` delegated to the same function, so
every policy with `AutoRotate: true` destroyed its secrets unattended)
**Files**: `internal/services/secrets/rotation_service.go`,
`internal/services/secrets/scheduler_service.go`, `cmd/rotation.go`
```

and append this section to the end of the entry, before the closing `---`:

```
**What was fixed**: `PerformManualRotation` now resolves its replacement value
from the request (`NewValue`, or `Generate` with `pwgen.Options`) and fails
with `ErrRotationValueRequired` rather than inventing one; archives the
pre-rotation plaintext through `versioningSvc.CreateVersion` before writing,
which is fatal on failure; and encrypts through `cryptoSvc.EncryptSecret`
before `secretRepo.Update`. `generateNewSecretValue` is deleted. The scheduler
sets `Generate: true` and no longer calls `CreateVersion` itself, which used to
write a second, doubly encrypted row. The CLI gained `--value`/`--generate`.
The regression test is
`TestPerformManualRotation_ExplicitValue_RoundTripsThroughGetSecret` in
`internal/services/secrets/rotation_roundtrip_test.go`.

**Recovery for data corrupted before this fix**: values rotated by the
scheduler survive in `secret_versions`, but doubly encrypted — a normal
`secrets versions get` returns the inner ciphertext, and recovering the
plaintext means decrypting that output once more with the master key. Values
rotated manually are **not recoverable**: the manual path never versioned, and
it overwrote the stored ciphertext in place. The only recovery for those is an
out-of-band copy (a database backup or `rocketvault backup` archive predating
the rotation, or the value as known to the system the secret belongs to). No
repair tooling was built; this was an explicit non-goal.
```

- [ ] **Step 4: Commit**

```bash
git add .claude/known-bugs.md
git commit -m "docs(bugs): close B35

Records the fix, and states plainly what is and is not recoverable for
secrets corrupted before it."
```

---

## Definition of Done

- Rotating a secret and reading it back returns the plaintext that was written;
  the test that proves it exists and is named after the assertion.
- Rotation with neither `--value` nor `--generate` fails with an error naming
  both, and touches nothing.
- Rotation with both is rejected.
- A manual rotation leaves exactly one new row in `secret_versions`, singly
  encrypted, holding the pre-rotation plaintext.
- A scheduled rotation does the same — one row, not two — and its secret still
  decrypts.
- `generateNewSecretValue` no longer exists anywhere in the tree
  (`grep -rn generateNewSecretValue .` returns nothing).
- `secrets rotation rotate --help` describes the real behavior, with no mention
  of `_rotated_` or "prefer secrets update".
- `go build ./...`, `go test ./...`, `gofmt -l .`, `go vet ./...` all clean.
- B35 is marked Fixed in `.claude/known-bugs.md`, carrying the recovery note.
