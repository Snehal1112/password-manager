package backup_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
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

func (r *stubSecretRepo) Read(_ context.Context, id uuid.UUID) (*model.Secret, error) {
	s, ok := r.secrets[id]
	if !ok {
		return nil, fmt.Errorf("secret not found")
	}
	cp := *s
	return &cp, nil
}

func (r *stubSecretRepo) ReadByOwner(_ context.Context, id, userID uuid.UUID) (*model.Secret, error) {
	s, ok := r.secrets[id]
	if !ok || s.UserID != userID {
		return nil, fmt.Errorf("secret not found or access denied")
	}
	cp := *s
	return &cp, nil
}

func (r *stubSecretRepo) Update(_ context.Context, s *model.Secret) error {
	if _, ok := r.secrets[s.ID]; !ok {
		return fmt.Errorf("secret not found")
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

func (r *stubSecretRepo) ListByUser(_ context.Context, userID uuid.UUID, _ []string) ([]model.Secret, error) {
	var out []model.Secret
	for _, s := range r.secrets {
		if s.UserID == userID {
			out = append(out, *s)
		}
	}
	return out, nil
}

func (r *stubSecretRepo) ListByUserIncludeDeleted(_ context.Context, userID uuid.UUID, _ []string) ([]model.Secret, error) {
	return r.ListByUser(context.Background(), userID, nil)
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
	err = svc.RestoreSecret(ctx, blob, userID, uuid.New())
	require.NoError(t, err)

	// Verify the restored secret matches the original data.
	restored, err := repo.ListByUser(ctx, userID, nil)
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

func (r *stubKeyRepo) Read(_ context.Context, id uuid.UUID) (*model.Key, error) {
	k, ok := r.keys[id]
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	cp := *k
	return &cp, nil
}

func (r *stubKeyRepo) Update(_ context.Context, k *model.Key) error {
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

func (r *stubKeyRepo) ListByUser(_ context.Context, _ *uuid.UUID, _ string, _ []string) ([]model.Key, error) {
	return nil, nil
}

func (r *stubKeyRepo) UpdateRevocationStatus(_ context.Context, _ uuid.UUID, _ bool) error {
	return nil
}

func (r *stubKeyRepo) SoftDelete(_ context.Context, _ uuid.UUID) error       { return nil }
func (r *stubKeyRepo) RecoverKey(_ context.Context, _ uuid.UUID) error        { return nil }
func (r *stubKeyRepo) PurgeKey(_ context.Context, _ uuid.UUID) error          { return nil }
func (r *stubKeyRepo) SetPurgeProtection(_ context.Context, _ uuid.UUID, _ bool) error {
	return nil
}

func (r *stubKeyRepo) ListSoftDeleted(_ context.Context, _ uuid.UUID) ([]*model.Key, error) {
	return nil, nil
}

func (r *stubKeyRepo) CreateVersion(_ context.Context, _ uuid.UUID, _ int, _ string) error {
	return nil
}

func (r *stubKeyRepo) ListVersions(_ context.Context, _, _ uuid.UUID) ([]model.KeyVersion, error) {
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

	err = svc.RestoreSecret(ctx, blob, userID, uuid.New())
	require.Error(t, err)
	require.Contains(t, err.Error(), "blob type mismatch")
}
