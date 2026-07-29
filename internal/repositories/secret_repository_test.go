package repositories_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// setupSecretTestDB creates an in-memory SQLite database for secret repository tests.
func setupSecretTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS secrets (
		id               TEXT PRIMARY KEY,
		user_id          TEXT NOT NULL,
		vault_id         TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-00000000efa1',
		name             TEXT NOT NULL,
		value            TEXT NOT NULL,
		version          INTEGER NOT NULL,
		created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at       TIMESTAMP NULL,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		scheduled_purge_at TIMESTAMP NULL,
		content_type     TEXT NOT NULL DEFAULT '',
		enabled          BOOLEAN NOT NULL DEFAULT TRUE,
		expires_at       TIMESTAMP NULL,
		not_before       TIMESTAMP NULL
	)`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

// newTestSecretLogger creates a logger suitable for use in repository tests.
func newTestSecretLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return &logging.Logger{Logger: l}
}

func TestSecretRepository_Read_OwnerScope_WrongUserReturnsError(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	ownerID := uuid.New()
	otherID := uuid.New()
	secret := &model.Secret{
		ID:              uuid.New(),
		UserID:          ownerID,
		Name:            "my-secret",
		Value:           "encrypted-data",
		Version:         1,
		CreatedAt:       time.Now().UTC(),
		PurgeProtection: false,
	}
	require.NoError(t, repo.Create(ctx, secret))

	// Owner can read their own secret.
	found, err := repo.Read(ctx, secret.ID, model.NewOwnerScope(uuid.Nil, ownerID))
	require.NoError(t, err)
	assert.Equal(t, secret.ID, found.ID)
	assert.Equal(t, ownerID, found.UserID)

	// Non-owner must receive an error — no data returned.
	_, err = repo.Read(ctx, secret.ID, model.NewOwnerScope(uuid.Nil, otherID))
	assert.Error(t, err, "an owner scope must fail for a wrong user_id")
	assert.Contains(t, err.Error(), "not found")
}

func TestSecretRepository_Read_OwnerScope_SoftDeletedSecretNotVisible(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	ownerID := uuid.New()
	secret := &model.Secret{
		ID:              uuid.New(),
		UserID:          ownerID,
		Name:            "deleted-secret",
		Value:           "encrypted-data",
		Version:         1,
		CreatedAt:       time.Now().UTC(),
		PurgeProtection: false,
	}
	require.NoError(t, repo.Create(ctx, secret))
	require.NoError(t, repo.SoftDelete(ctx, secret.ID))

	// Even the owner cannot read a soft-deleted secret via an owner scope.
	_, err := repo.Read(ctx, secret.ID, model.NewOwnerScope(uuid.Nil, ownerID))
	assert.Error(t, err, "an owner scope must not return a soft-deleted secret")
	assert.Contains(t, err.Error(), "not found")
}

// TestSecretLifecycleAttributes_PersistAndLoad verifies that enabled, expires_at,
// and not_before are stored and loaded correctly from the database.
func TestSecretLifecycleAttributes_PersistAndLoad(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))

	now := time.Now()
	exp := now.Add(24 * time.Hour)
	nbf := now.Add(-1 * time.Hour)

	s := &model.Secret{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		Name:      "test-lifecycle",
		Value:     "encrypted-value",
		Version:   1,
		CreatedAt: now,
		Enabled:   true,
		ExpiresAt: &exp,
		NotBefore: &nbf,
	}
	require.NoError(t, repo.Create(context.Background(), s))

	loaded, err := repo.Read(context.Background(), s.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
	require.True(t, loaded.Enabled)
	require.NotNil(t, loaded.ExpiresAt)
	require.WithinDuration(t, exp, *loaded.ExpiresAt, time.Second)
	require.NotNil(t, loaded.NotBefore)
}

// TestSecretRepository_List_VaultScope_ScopesByVault verifies that a vault
// scope returns only secrets belonging to the requested vault.
func TestSecretRepository_List_VaultScope_ScopesByVault(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()
	vaultA, vaultB := uuid.New(), uuid.New()

	mk := func(name string, v uuid.UUID) *model.Secret {
		return &model.Secret{ID: uuid.New(), UserID: uuid.New(), VaultID: v, Name: name, Value: "x", Version: 1, CreatedAt: time.Now(), Enabled: true}
	}
	require.NoError(t, repo.Create(ctx, mk("a", vaultA)))
	require.NoError(t, repo.Create(ctx, mk("b", vaultA)))
	require.NoError(t, repo.Create(ctx, mk("c", vaultB)))

	gotA, err := repo.List(ctx, model.NewVaultScope(vaultA, uuid.Nil), repositories.SecretFilter{})
	require.NoError(t, err)
	require.Len(t, gotA, 2)
	gotB, err := repo.List(ctx, model.NewVaultScope(vaultB, uuid.Nil), repositories.SecretFilter{})
	require.NoError(t, err)
	require.Len(t, gotB, 1)
}

// TestListVaultScope_PopulatesVaultID verifies that a vault-scoped List sets
// VaultID on each returned secret to the vault it was queried with.
func TestListVaultScope_PopulatesVaultID(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()
	vaultA := uuid.New()

	mk := func(name string) *model.Secret {
		return &model.Secret{ID: uuid.New(), UserID: uuid.New(), VaultID: vaultA, Name: name, Value: "x", Version: 1, CreatedAt: time.Now(), Enabled: true}
	}
	require.NoError(t, repo.Create(ctx, mk("a")))
	require.NoError(t, repo.Create(ctx, mk("b")))

	got, err := repo.List(ctx, model.NewVaultScope(vaultA, uuid.Nil), repositories.SecretFilter{})
	require.NoError(t, err)
	require.Len(t, got, 2)
	for _, s := range got {
		assert.Equal(t, vaultA, s.VaultID, "a vault-scoped List must populate VaultID on returned secrets")
	}
}

// TestListVaultScopeIncludeDeleted_PopulatesVaultID verifies that a
// vault-scoped List with IncludeDeleted sets VaultID on each returned secret.
func TestListVaultScopeIncludeDeleted_PopulatesVaultID(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()
	vaultA := uuid.New()

	mk := func(name string) *model.Secret {
		return &model.Secret{ID: uuid.New(), UserID: uuid.New(), VaultID: vaultA, Name: name, Value: "x", Version: 1, CreatedAt: time.Now(), Enabled: true}
	}
	require.NoError(t, repo.Create(ctx, mk("a")))
	require.NoError(t, repo.Create(ctx, mk("b")))
	require.NoError(t, repo.SoftDeleteVaultContents(ctx, vaultA, time.Now()))

	got, err := repo.List(ctx, model.NewVaultScope(vaultA, uuid.Nil), repositories.SecretFilter{IncludeDeleted: true})
	require.NoError(t, err)
	require.Len(t, got, 2)
	for _, s := range got {
		assert.Equal(t, vaultA, s.VaultID, "a vault-scoped List must populate VaultID on returned secrets")
	}
}

// TestSecretRepository_Update_VaultScope_UpdatesWhenVaultMatches verifies that
// a vault-scoped Update applies when the secret belongs to the given vault.
func TestSecretRepository_Update_VaultScope_UpdatesWhenVaultMatches(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	vaultID := uuid.New()
	secret := &model.Secret{
		ID: uuid.New(), UserID: uuid.New(), VaultID: vaultID,
		Name: "s1", Value: "enc-v1", Version: 1, CreatedAt: time.Now(), Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, secret))

	secret.Name = "s1-renamed"
	secret.Value = "enc-v2"
	secret.Version = 2
	err := repo.Update(ctx, secret, model.NewVaultScope(vaultID, uuid.Nil))
	require.NoError(t, err)

	got, err := repo.Read(ctx, secret.ID, model.NewVaultScope(vaultID, uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, "s1-renamed", got.Name)
	assert.Equal(t, "enc-v2", got.Value)
	assert.Equal(t, 2, got.Version)
}

// TestSecretRepository_Update_VaultScope_NoOpWhenVaultMismatch verifies that
// a vault-scoped Update fails (and leaves the row unchanged) when the scope's
// vault does not match the vault the row actually belongs to.
func TestSecretRepository_Update_VaultScope_NoOpWhenVaultMismatch(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	realVault := uuid.New()
	secret := &model.Secret{
		ID: uuid.New(), UserID: uuid.New(), VaultID: realVault,
		Name: "s1", Value: "enc-v1", Version: 1, CreatedAt: time.Now(), Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, secret))

	secret.Name = "should-not-apply"
	err := repo.Update(ctx, secret, model.NewVaultScope(uuid.New(), uuid.Nil)) // wrong vault
	require.Error(t, err)

	got, err := repo.Read(ctx, secret.ID, model.NewVaultScope(realVault, uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, "s1", got.Name) // unchanged
}

// TestSecretRepository_SoftDeleteVaultContents_HidesFromList verifies that after
// soft-deleting a vault's contents, a vault-scoped List returns nothing while
// IncludeDeleted still returns the rows.
func TestSecretRepository_SoftDeleteVaultContents_HidesFromList(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()
	vaultA := uuid.New()

	mk := func(name string) *model.Secret {
		return &model.Secret{ID: uuid.New(), UserID: uuid.New(), VaultID: vaultA, Name: name, Value: "x", Version: 1, CreatedAt: time.Now(), Enabled: true}
	}
	require.NoError(t, repo.Create(ctx, mk("a")))
	require.NoError(t, repo.Create(ctx, mk("b")))

	require.NoError(t, repo.SoftDeleteVaultContents(ctx, vaultA, time.Now()))

	active, err := repo.List(ctx, model.NewVaultScope(vaultA, uuid.Nil), repositories.SecretFilter{})
	require.NoError(t, err)
	require.Len(t, active, 0)

	all, err := repo.List(ctx, model.NewVaultScope(vaultA, uuid.Nil), repositories.SecretFilter{IncludeDeleted: true})
	require.NoError(t, err)
	require.Len(t, all, 2)
}

// TestSecretRepository_RecoverVaultContents_OnlyRestoresCascadeDeleted verifies that
// recovering a vault restores ONLY the rows the vault cascade soft-deleted (matched
// by the cascade timestamp), and does NOT resurrect a secret the user had
// individually soft-deleted earlier.
func TestSecretRepository_RecoverVaultContents_OnlyRestoresCascadeDeleted(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()
	vaultA := uuid.New()

	mk := func(name string) *model.Secret {
		return &model.Secret{ID: uuid.New(), UserID: uuid.New(), VaultID: vaultA, Name: name, Value: "x", Version: 1, CreatedAt: time.Now(), Enabled: true}
	}
	keep := mk("active")        // stays active
	indiv := mk("user-deleted") // user deletes this one individually, before vault delete
	require.NoError(t, repo.Create(ctx, keep))
	require.NoError(t, repo.Create(ctx, indiv))

	// User individually soft-deletes "user-deleted".
	require.NoError(t, repo.SoftDelete(ctx, indiv.ID))

	// Vault is deleted: cascade soft-deletes the remaining active rows at vaultDeletedAt.
	vaultDeletedAt := time.Now().Add(time.Hour) // distinct from the individual delete time
	require.NoError(t, repo.SoftDeleteVaultContents(ctx, vaultA, vaultDeletedAt))

	// Vault is recovered: only the cascade-deleted rows should come back.
	require.NoError(t, repo.RecoverVaultContents(ctx, vaultA, vaultDeletedAt))

	active, err := repo.List(ctx, model.NewVaultScope(vaultA, uuid.Nil), repositories.SecretFilter{})
	require.NoError(t, err)
	// Only "active" should be live again; "user-deleted" must remain soft-deleted.
	require.Len(t, active, 1)
	require.Equal(t, "active", active[0].Name)
}

// TestSoftDelete_PreservesPurgeProtection verifies that SoftDelete does not
// overwrite a pre-existing purge_protection = TRUE on a secret.
func TestSoftDelete_PreservesPurgeProtection(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	ownerID := uuid.New()
	secret := &model.Secret{
		ID:              uuid.New(),
		UserID:          ownerID,
		Name:            "protected-secret",
		Value:           "encrypted-data",
		Version:         1,
		CreatedAt:       time.Now().UTC(),
		PurgeProtection: false,
	}
	require.NoError(t, repo.Create(ctx, secret))

	// Enable purge protection directly — SecretRepositoryInterface has no SetPurgeProtection.
	_, err := db.ExecContext(ctx,
		"UPDATE secrets SET purge_protection = TRUE WHERE id = ?", secret.ID.String())
	require.NoError(t, err)

	// SoftDelete must not reset purge_protection to FALSE.
	require.NoError(t, repo.SoftDelete(ctx, secret.ID))

	var pp bool
	err = db.QueryRowContext(ctx,
		"SELECT purge_protection FROM secrets WHERE id = ?", secret.ID.String()).Scan(&pp)
	require.NoError(t, err)
	assert.True(t, pp, "SoftDelete must not overwrite purge_protection")
}

func TestSecretRepository_SoftDeleteVaultContentsTx_CommitsWithSharedTx(t *testing.T) {
	db := setupSecretTestDB(t)
	conn := rvdb.NewConn(db, rvdb.SQLite)
	// SoftDeleteVaultContentsTx is intentionally not part of SecretRepositoryInterface
	// (see internal/repositories/secret_repository.go); assert to the concrete type
	// to reach it, the way a same-package cascade caller would.
	repo := repositories.NewSecretRepository(conn, newTestSecretLogger(t)).(*repositories.SecretRepository)
	ctx := context.Background()

	vaultID := uuid.New()
	secret := &model.Secret{
		ID: uuid.New(), UserID: uuid.New(), VaultID: vaultID, Name: "s", Value: "enc",
		Version: 1, CreatedAt: time.Now().UTC(), Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, secret))

	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, repo.SoftDeleteVaultContentsTx(ctx, tx, vaultID, time.Now().UTC()))
	require.NoError(t, tx.Commit())

	_, err = repo.Read(ctx, secret.ID, model.NewAdminScope(uuid.Nil))
	require.Error(t, err, "secret must be hidden after commit")
}

func TestSecretRepository_SoftDeleteVaultContentsTx_RollsBackWithSharedTx(t *testing.T) {
	db := setupSecretTestDB(t)
	conn := rvdb.NewConn(db, rvdb.SQLite)
	// See the comment in the Commits variant above for why we assert to the concrete type.
	repo := repositories.NewSecretRepository(conn, newTestSecretLogger(t)).(*repositories.SecretRepository)
	ctx := context.Background()

	vaultID := uuid.New()
	secret := &model.Secret{
		ID: uuid.New(), UserID: uuid.New(), VaultID: vaultID, Name: "s", Value: "enc",
		Version: 1, CreatedAt: time.Now().UTC(), Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, secret))

	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, repo.SoftDeleteVaultContentsTx(ctx, tx, vaultID, time.Now().UTC()))
	require.NoError(t, tx.Rollback())

	_, err = repo.Read(ctx, secret.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err, "secret must still be active after rollback")
}

// fakeAuditPersister records every persisted audit event's actor (userID)
// for assertions. It implements logging.AuditPersister.
type fakeAuditPersister struct {
	actors []string
}

func (f *fakeAuditPersister) PersistAudit(userID, action, details string) error {
	f.actors = append(f.actors, userID)
	return nil
}

// TestSecretRepository_Update_VaultScope_DoesNotAudit proves that a
// vault-scoped Update emits no repository-level audit row. Audit attribution
// belongs solely to the service layer, which knows the real acting principal
// from the request; the repository only has a Scope.
func TestSecretRepository_Update_VaultScope_DoesNotAudit(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	logger := newTestSecretLogger(t)
	persister := &fakeAuditPersister{}
	logger.SetAuditPersister(persister)

	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), logger)
	ctx := context.Background()

	ownerID := uuid.New()
	vaultID := uuid.New()
	secretID := uuid.New()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID: secretID, UserID: ownerID, VaultID: vaultID, Name: "s", Value: "enc", Version: 1,
	}))

	// Create() legitimately attributes its own audit row to the owner; reset
	// here so the assertion below only covers the Update call under test.
	persister.actors = nil

	err := repo.Update(ctx, &model.Secret{
		ID: secretID, UserID: ownerID, VaultID: vaultID, Name: "s2", Value: "enc2", Version: 2,
	}, model.NewVaultScope(vaultID, uuid.Nil))
	require.NoError(t, err)

	assert.Empty(t, persister.actors,
		"Update must not emit a repository-level audit row; attribution lives solely in the service layer")
}

// TestSecretRepository_Read_PopulatesVaultID pins the prerequisite fix from the
// P1 spec: Read must select vault_id under both a vault scope and an owner
// scope, so a scope-aware write can never be handed an entity with a zero
// VaultID.
func TestSecretRepository_Read_PopulatesVaultID(t *testing.T) {
	t.Parallel()
	db := setupSecretTestDB(t)
	repo := repositories.NewSecretRepository(rvdb.NewConn(db, rvdb.SQLite), newTestSecretLogger(t))
	ctx := context.Background()

	ownerID := uuid.New()
	vaultID := uuid.New()
	secret := &model.Secret{
		ID:        uuid.New(),
		UserID:    ownerID,
		VaultID:   vaultID,
		Name:      "vault-scoped-secret",
		Value:     "encrypted-data",
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Enabled:   true,
	}
	require.NoError(t, repo.Create(ctx, secret))

	byID, err := repo.Read(ctx, secret.ID, model.NewAdminScope(uuid.Nil))
	require.NoError(t, err)
	assert.Equal(t, vaultID, byID.VaultID, "Read must populate VaultID")

	byOwner, err := repo.Read(ctx, secret.ID, model.NewOwnerScope(uuid.Nil, ownerID))
	require.NoError(t, err)
	assert.Equal(t, vaultID, byOwner.VaultID, "an owner-scoped Read must populate VaultID")
}
