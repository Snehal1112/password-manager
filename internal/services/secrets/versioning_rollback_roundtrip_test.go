package secrets_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
	"rocketvault/internal/services/secrets"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// rollbackFixture wires the real repositories, the real cryptography service
// and a real database. Mocked crypto cannot prove a round trip, and a round
// trip is the whole point of these tests. It reuses rotationFixtureSchema
// because rollback touches the same tables.
type rollbackFixture struct {
	conn          *sql.DB
	crypto        secrets.CryptographyService
	versioningSvc secrets.VersioningServiceInterface
	secretSvc     secrets.SecretService
	versionRepo   repositories.SecretVersionRepositoryInterface
	userID        uuid.UUID
	vaultID       uuid.UUID
	secretID      uuid.UUID
}

// scope returns the vault scope a CLI caller would use.
func (f *rollbackFixture) scope() model.Scope {
	return model.NewVaultScope(f.vaultID, f.userID)
}

// newRollbackFixture seeds one owner and one secret at version 1 holding the
// given plaintext, encrypted exactly the way the service layer stores it.
func newRollbackFixture(t *testing.T, plaintext string) *rollbackFixture {
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
	versionRepo := repositories.NewSecretVersionRepository(dbConn, log)
	userRepo := repositories.NewUserRepository(dbConn, log)
	tagRepo := repositories.NewSecretTagRepository(dbConn)

	crypto := secrets.NewCryptographyService()
	versioningSvc := secrets.NewVersioningService(versionRepo, secretRepo, userRepo, crypto, log, nil)
	secretSvc := secrets.NewSecretService(secrets.SecretServiceConfig{
		SecretRepository: secretRepo,
		CryptoService:    crypto,
		VersionService:   versioningSvc,
		TagService:       secrets.NewTagService(tagRepo, log),
		Logger:           log,
	})

	f := &rollbackFixture{
		conn:          conn,
		crypto:        crypto,
		versioningSvc: versioningSvc,
		secretSvc:     secretSvc,
		versionRepo:   versionRepo,
		userID:        uuid.New(),
		vaultID:       uuid.New(),
		secretID:      uuid.New(),
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

	return f
}

// updateValue drives the normal update path, which archives the current
// plaintext as a version and stores the new value re-encrypted.
func (f *rollbackFixture) updateValue(t *testing.T, ctx context.Context, newValue string) {
	t.Helper()
	require.NoError(t, f.secretSvc.UpdateSecret(ctx, secrets.UpdateSecretRequest{
		SecretID: f.secretID,
		Scope:    f.scope(),
		Value:    &newValue,
	}))
}

// storedSecretValue returns the raw secrets.value column, bypassing every
// service that would decrypt it on the way out.
func (f *rollbackFixture) storedSecretValue(t *testing.T) string {
	t.Helper()
	var stored string
	require.NoError(t, f.conn.QueryRow(
		`SELECT value FROM secrets WHERE id = ?`, f.secretID.String()).Scan(&stored))
	return stored
}

// versionValue returns the decrypted value of one archived version row.
func (f *rollbackFixture) versionValue(t *testing.T, ctx context.Context, version int) string {
	t.Helper()
	versions, err := f.versionRepo.GetVersions(ctx, f.secretID)
	require.NoError(t, err)
	for _, v := range versions {
		if v.Version == version {
			plaintext, decErr := f.crypto.DecryptSecret(v.Value)
			require.NoError(t, decErr, "version %d must be singly encrypted, not encrypted ciphertext", version)
			return plaintext
		}
	}
	t.Fatalf("no archived row for version %d", version)
	return ""
}

// TestRollbackToVersion_RoundTripsThroughGetSecret is the test whose absence
// let B46 ship: nothing ever rolled a secret back and then read it back. The
// rollback used to store the target plaintext straight into the ciphertext
// column, so the next read could never decrypt it again.
func TestRollbackToVersion_RoundTripsThroughGetSecret(t *testing.T) {
	ctx := context.Background()
	f := newRollbackFixture(t, "v1-original")

	f.updateValue(t, ctx, "v2-current")

	rolledBack, err := f.versioningSvc.RollbackToVersion(ctx, secrets.RollbackRequest{
		SecretID:      f.secretID,
		TargetVersion: 1,
		UserID:        f.userID,
	})
	require.NoError(t, err)
	assert.Equal(t, 4, rolledBack.Version, "rollback lands beyond the backup version it just wrote")

	// The directly returned secret must carry plaintext, the way CreateSecret
	// hands plaintext back. The ciphertext exists only for the repository
	// write, so a caller must never see it here.
	assert.Equal(t, "v1-original", rolledBack.Value,
		"the returned secret must hold plaintext, not the value written to the database")
	storedValue := f.storedSecretValue(t)
	assert.NotEqual(t, rolledBack.Value, storedValue,
		"the column must hold ciphertext even though the return value holds plaintext")

	got, err := f.secretSvc.GetSecret(ctx, f.secretID, f.scope())
	require.NoError(t, err, "a rolled-back secret must still decrypt")
	assert.Equal(t, "v1-original", got.Value)
	assert.Equal(t, 4, got.Version)
}

// TestRollbackToVersion_ArchivesThePreRollbackValue pins the other half of B46:
// the backup version was built from the stored ciphertext and CreateVersion
// encrypted it again, so the pre-rollback state was unrecoverable garbage.
func TestRollbackToVersion_ArchivesThePreRollbackValue(t *testing.T) {
	ctx := context.Background()
	f := newRollbackFixture(t, "v1-original")

	f.updateValue(t, ctx, "v2-current")

	_, err := f.versioningSvc.RollbackToVersion(ctx, secrets.RollbackRequest{
		SecretID:      f.secretID,
		TargetVersion: 1,
		UserID:        f.userID,
	})
	require.NoError(t, err)

	versions, err := f.versionRepo.GetVersions(ctx, f.secretID)
	require.NoError(t, err)
	require.Len(t, versions, 2, "one row from the update, one backup row from the rollback")

	assert.Equal(t, "v1-original", f.versionValue(t, ctx, 1), "the update's archived row must stay readable")
	assert.Equal(t, "v2-current", f.versionValue(t, ctx, 3),
		"the pre-rollback backup must decrypt in one pass, not be doubly encrypted")
}

// TestRollbackToVersion_LeavesTheSecretWritable covers the blast radius of the
// plaintext write: every later writer decrypts the stored value first, so a
// rollback that stored plaintext bricked the secret for updates too, not only
// for reads.
func TestRollbackToVersion_LeavesTheSecretWritable(t *testing.T) {
	ctx := context.Background()
	f := newRollbackFixture(t, "v1-original")

	f.updateValue(t, ctx, "v2-current")

	_, err := f.versioningSvc.RollbackToVersion(ctx, secrets.RollbackRequest{
		SecretID:      f.secretID,
		TargetVersion: 1,
		UserID:        f.userID,
	})
	require.NoError(t, err)

	newValue := "v5-after-rollback"
	require.NoError(t, f.secretSvc.UpdateSecret(ctx, secrets.UpdateSecretRequest{
		SecretID: f.secretID,
		Scope:    f.scope(),
		Value:    &newValue,
	}), "an update after a rollback must still be able to decrypt the stored value")

	got, err := f.secretSvc.GetSecret(ctx, f.secretID, f.scope())
	require.NoError(t, err)
	assert.Equal(t, newValue, got.Value)

	assert.Equal(t, "v1-original", f.versionValue(t, ctx, 4),
		"that update must archive the rolled-back value, still singly encrypted")
}
