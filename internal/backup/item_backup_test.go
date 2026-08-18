package backup_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// stubSecretRepo is a minimal in-memory secret repository for testing.
type stubSecretRepo struct {
	secrets map[uuid.UUID]*model.Secret
}

func newStubSecretRepo() *stubSecretRepo {
	return &stubSecretRepo{secrets: make(map[uuid.UUID]*model.Secret)}
}

func (r *stubSecretRepo) Create(_ context.Context, s *model.Secret) error {
	if _, exists := r.secrets[s.ID]; exists {
		return fmt.Errorf("secret already exists: %s", s.ID)
	}
	cp := *s
	r.secrets[s.ID] = &cp
	return nil
}

// scopeAuthorizes mirrors the real repository's scopePredicate: it decides
// whether a secret is reachable under the given scope.
func scopeAuthorizes(s *model.Secret, scope model.Scope) bool {
	switch scope.Kind() {
	case model.ScopeVault:
		return s.VaultID == scope.VaultID()
	case model.ScopeOwner:
		ownerID, ok := scope.OwnerID()
		return ok && s.UserID == ownerID
	case model.ScopeAdmin:
		return true
	default:
		return false
	}
}

func (r *stubSecretRepo) Read(_ context.Context, id uuid.UUID, scope model.Scope) (*model.Secret, error) {
	s, ok := r.secrets[id]
	if !ok || !scopeAuthorizes(s, scope) {
		return nil, fmt.Errorf("secret not found or access denied")
	}
	cp := *s
	return &cp, nil
}

func (r *stubSecretRepo) Update(_ context.Context, s *model.Secret, scope model.Scope) error {
	existing, ok := r.secrets[s.ID]
	if !ok || !scopeAuthorizes(existing, scope) {
		return fmt.Errorf("secret not found or access denied")
	}
	cp := *s
	r.secrets[s.ID] = &cp
	return nil
}

func (r *stubSecretRepo) Delete(_ context.Context, id uuid.UUID) error {
	delete(r.secrets, id)
	return nil
}

func (r *stubSecretRepo) SoftDelete(_ context.Context, id uuid.UUID) error {
	s, ok := r.secrets[id]
	if !ok {
		return fmt.Errorf("secret not found")
	}
	now := time.Now()
	s.DeletedAt = &now
	return nil
}

func (r *stubSecretRepo) RecoverSecret(_ context.Context, id uuid.UUID) error {
	s, ok := r.secrets[id]
	if !ok {
		return fmt.Errorf("secret not found")
	}
	s.DeletedAt = nil
	return nil
}

func (r *stubSecretRepo) List(_ context.Context, scope model.Scope, filter repositories.SecretFilter) ([]model.Secret, error) {
	var out []model.Secret
	for _, s := range r.secrets {
		if !scopeAuthorizes(s, scope) {
			continue
		}
		switch {
		case filter.OnlyDeleted:
			if s.DeletedAt == nil {
				continue
			}
		case filter.IncludeDeleted:
			// No deleted_at constraint.
		default:
			if s.DeletedAt != nil {
				continue
			}
		}
		out = append(out, *s)
	}
	return out, nil
}

func (r *stubSecretRepo) ExportSecrets(_ context.Context, _ model.ExportOptions) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *stubSecretRepo) ImportSecrets(_ context.Context, _ []byte, _ model.ImportOptions) (int, error) {
	return 0, fmt.Errorf("not implemented")
}

func (r *stubSecretRepo) GetVersions(_ context.Context, _ uuid.UUID) ([]model.SecretVersion, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *stubSecretRepo) GetVersion(_ context.Context, _ uuid.UUID, _ int) (*model.SecretVersion, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *stubSecretRepo) GetLatestVersion(_ context.Context, _ uuid.UUID) (*model.SecretVersion, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *stubSecretRepo) PurgeSecret(_ context.Context, id uuid.UUID) error {
	delete(r.secrets, id)
	return nil
}

func (r *stubSecretRepo) SoftDeleteVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return nil
}

func (r *stubSecretRepo) RecoverVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return nil
}

func TestBackupRestoreSecret(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	repo := newStubSecretRepo()
	original := &model.Secret{
		ID:      secretID,
		UserID:  userID,
		Name:    "my-db-password",
		Value:   "s3cr3t",
		Version: 1,
		Tags:    []string{"db", "prod"},
		Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, original))

	svc := backup.NewItemBackupService(repo, nil, nil)

	// Backup the secret.
	blob, err := svc.BackupSecret(ctx, secretID, userID)
	require.NoError(t, err)
	require.NotEmpty(t, blob)

	// Remove the original so restore has a clean target.
	require.NoError(t, repo.Delete(ctx, secretID))

	// Restore using a new UUID so no collision.
	err = svc.RestoreSecret(ctx, blob, userID, uuid.New(), uuid.New())
	require.NoError(t, err)

	// Verify the restored secret matches the original data.
	restored, err := repo.List(ctx, model.NewOwnerScope(uuid.Nil, userID), repositories.SecretFilter{})
	require.NoError(t, err)
	require.Len(t, restored, 1)
	require.Equal(t, original.Name, restored[0].Name)
	require.Equal(t, original.Value, restored[0].Value)
	require.Equal(t, original.Version, restored[0].Version)
}

func TestBackupSecretForbidden(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	otherID := uuid.New()
	secretID := uuid.New()

	repo := newStubSecretRepo()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID:      secretID,
		UserID:  ownerID,
		Name:    "private",
		Value:   "value",
		Version: 1,
		Enabled: true,
	}))

	svc := backup.NewItemBackupService(repo, nil, nil)

	// A different user must not be able to back up another user's secret.
	_, err := svc.BackupSecret(ctx, secretID, otherID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "forbidden")
}

// stubKeyRepo is a minimal in-memory key repository for testing.
type stubKeyRepo struct {
	keys map[uuid.UUID]*model.Key
}

func newStubKeyRepo() *stubKeyRepo {
	return &stubKeyRepo{keys: make(map[uuid.UUID]*model.Key)}
}

func (r *stubKeyRepo) Create(_ context.Context, k *model.Key) error {
	if _, exists := r.keys[k.ID]; exists {
		return fmt.Errorf("key already exists: %s", k.ID)
	}
	cp := *k
	r.keys[k.ID] = &cp
	return nil
}

// Read ignores scope: BackupKey/RestoreKey pass an admin scope (the read
// itself is unchecked) and enforce ownership manually afterward, matching
// item_backup.go's actual behaviour.
func (r *stubKeyRepo) Read(_ context.Context, id uuid.UUID, _ model.Scope) (*model.Key, error) {
	k, ok := r.keys[id]
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	cp := *k
	return &cp, nil
}

func (r *stubKeyRepo) Update(_ context.Context, k *model.Key, _ model.Scope) error {
	if _, ok := r.keys[k.ID]; !ok {
		return fmt.Errorf("key not found")
	}
	cp := *k
	r.keys[k.ID] = &cp
	return nil
}

func (r *stubKeyRepo) Delete(_ context.Context, id uuid.UUID) error {
	delete(r.keys, id)
	return nil
}

func (r *stubKeyRepo) UpdateRevocationStatus(_ context.Context, _ uuid.UUID, _ bool) error {
	return nil
}

func (r *stubKeyRepo) SoftDelete(_ context.Context, _ uuid.UUID) error { return nil }
func (r *stubKeyRepo) RecoverKey(_ context.Context, _ uuid.UUID) error { return nil }
func (r *stubKeyRepo) PurgeKey(_ context.Context, _ uuid.UUID) error   { return nil }
func (r *stubKeyRepo) SetPurgeProtection(_ context.Context, _ uuid.UUID, _ bool) error {
	return nil
}

func (r *stubKeyRepo) ReadDeleted(_ context.Context, _ uuid.UUID) (*model.Key, error) {
	return nil, nil
}

func (r *stubKeyRepo) CreateVersion(_ context.Context, _ uuid.UUID, _ int, _ string) error {
	return nil
}

func (r *stubKeyRepo) ListVersions(_ context.Context, _, _ uuid.UUID) ([]model.KeyVersion, error) {
	return nil, nil
}

func (r *stubKeyRepo) SoftDeleteVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return nil
}

func (r *stubKeyRepo) RecoverVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return nil
}

func (r *stubKeyRepo) List(_ context.Context, _ model.Scope, _ repositories.KeyFilter) ([]model.Key, error) {
	return nil, nil
}

func TestRestoreSecretBlobTypeMismatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	keyID := uuid.New()

	// Build a key backup blob via the key path so it has resource_type="key".
	keyRepo := newStubKeyRepo()
	require.NoError(t, keyRepo.Create(ctx, &model.Key{
		ID:      keyID,
		UserID:  userID,
		Name:    "my-key",
		Value:   "key-value",
		Type:    model.KeyTypeRSA,
		Enabled: true,
	}))

	svc := backup.NewItemBackupService(newStubSecretRepo(), keyRepo, nil)

	// Backup a key but try to restore it as a secret.
	blob, err := svc.BackupKey(ctx, keyID, userID)
	require.NoError(t, err)

	err = svc.RestoreSecret(ctx, blob, userID, uuid.New(), uuid.New())
	require.Error(t, err)
	require.True(t, errors.Is(err, backup.ErrInvalidBlob), "expected ErrInvalidBlob, got: %v", err)
}

// TestRestoreSecretWritesAuthorizedVaultNotBlobVault verifies that
// RestoreSecret writes the vault ID authorized by the caller's request, not
// the vault ID embedded in the backup blob. A user with restore permission
// in vault B, restoring a blob whose embedded vault is A, must land the
// restored secret in vault B — not silently write into vault A.
func TestRestoreSecretWritesAuthorizedVaultNotBlobVault(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := newStubSecretRepo()
	svc := backup.NewItemBackupService(repo, nil, nil)

	vaultA := uuid.New()
	vaultB := uuid.New()
	owner := uuid.New()

	original := &model.Secret{
		ID:      uuid.New(),
		UserID:  owner,
		VaultID: vaultA,
		Name:    "s1",
		Value:   "v1",
		Version: 1,
		Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, original))

	blob, err := svc.BackupSecret(ctx, original.ID, owner)
	require.NoError(t, err)

	newID := uuid.New()
	err = svc.RestoreSecret(ctx, blob, owner, vaultB, newID)
	require.NoError(t, err)

	restored, err := repo.Read(ctx, newID, model.NewVaultScope(vaultB, owner))
	require.NoError(t, err)
	assert.Equal(t, vaultB, restored.VaultID, "restore must write the authorized vault, not the blob's embedded vault")

	_, err = repo.Read(ctx, newID, model.NewVaultScope(vaultA, owner))
	require.Error(t, err, "the restored secret must not be readable under the blob's original vault scope")
}
