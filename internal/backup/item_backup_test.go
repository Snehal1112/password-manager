package backup_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
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
	// LastReadScope records the scope of the most recent Read. The stub
	// itself ignores scope for its own gating (it applies scopeAuthorizes
	// directly against the in-memory map), but this lets tests assert the
	// exact scope the service passed — the real predicate lives in
	// SecretRepository's SQL.
	LastReadScope model.Scope
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
	r.LastReadScope = scope
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

func (r *stubSecretRepo) SetPurgeProtection(_ context.Context, id uuid.UUID, enabled bool) error {
	if s, ok := r.secrets[id]; ok {
		s.PurgeProtection = enabled
	}
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
	blob, err := svc.BackupSecret(ctx, secretID, userID, uuid.Nil)
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

func TestBackupSecretNonOwnerInSameVaultSucceeds(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	callerID := uuid.New()
	vaultID := uuid.New()
	secretID := uuid.New()

	repo := newStubSecretRepo()
	require.NoError(t, repo.Create(ctx, &model.Secret{
		ID:      secretID,
		UserID:  ownerID,
		VaultID: vaultID,
		Name:    "shared",
		Value:   "value",
		Version: 1,
		Enabled: true,
	}))

	svc := backup.NewItemBackupService(repo, nil, nil)

	// A Secrets Officer authorized in this vault who does not own the secret
	// must be able to back it up.
	blob, err := svc.BackupSecret(ctx, secretID, callerID, vaultID)
	require.NoError(t, err)
	require.NotEmpty(t, blob)
	require.Equal(t, model.NewVaultScope(vaultID, callerID), repo.LastReadScope)
}

// stubKeyRepo is a minimal in-memory key repository for testing.
type stubKeyRepo struct {
	keys     map[uuid.UUID]*model.Key
	versions map[uuid.UUID]map[int]string
	// LastReadScope records the scope of the most recent Read. The stub itself
	// ignores scope (it is an in-memory map), so the scope the service passes
	// is asserted directly — the real predicate lives in KeyRepository's SQL.
	LastReadScope model.Scope
}

func newStubKeyRepo() *stubKeyRepo {
	return &stubKeyRepo{
		keys:     make(map[uuid.UUID]*model.Key),
		versions: make(map[uuid.UUID]map[int]string),
	}
}

func (r *stubKeyRepo) Create(_ context.Context, k *model.Key) error {
	if _, exists := r.keys[k.ID]; exists {
		return fmt.Errorf("key already exists: %s", k.ID)
	}
	cp := *k
	r.keys[k.ID] = &cp
	return nil
}

// Read ignores scope for authorization purposes: it is an in-memory map with
// no SQL predicate to enforce. It still records the scope it was called with
// so tests can assert the service passed the correct one; the real predicate
// lives in KeyRepository's SQL.
func (r *stubKeyRepo) Read(_ context.Context, id uuid.UUID, scope model.Scope) (*model.Key, error) {
	r.LastReadScope = scope
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
func (r *stubKeyRepo) SetPurgeProtection(_ context.Context, id uuid.UUID, enabled bool) error {
	if k, ok := r.keys[id]; ok {
		k.PurgeProtection = enabled
	}
	return nil
}

func (r *stubKeyRepo) ReadDeleted(_ context.Context, _ uuid.UUID) (*model.Key, error) {
	return nil, nil
}

func (r *stubKeyRepo) CreateVersion(_ context.Context, keyID uuid.UUID, version int, value string) error {
	if r.versions[keyID] == nil {
		r.versions[keyID] = make(map[int]string)
	}
	r.versions[keyID][version] = value
	return nil
}

func (r *stubKeyRepo) ListVersions(_ context.Context, keyID uuid.UUID) ([]model.KeyVersion, error) {
	var out []model.KeyVersion
	for v := range r.versions[keyID] {
		out = append(out, model.KeyVersion{KeyID: keyID, Version: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// CurrentVersion mirrors the repository's aggregate: the highest stored
// version, or the implicit 1 when the key has never been rotated.
func (r *stubKeyRepo) CurrentVersion(_ context.Context, keyID uuid.UUID) (int, error) {
	current := 1
	for v := range r.versions[keyID] {
		if v > current {
			current = v
		}
	}
	return current, nil
}

func (r *stubKeyRepo) ReadVersionValue(_ context.Context, _ uuid.UUID, _ int) (string, error) {
	return "", nil
}

func (r *stubKeyRepo) GetVersion(_ context.Context, _ uuid.UUID, _ int) (*model.KeyVersion, error) {
	return nil, nil
}

func (r *stubKeyRepo) ListVersionRecords(_ context.Context, keyID uuid.UUID) ([]model.KeyVersionRecord, error) {
	var records []model.KeyVersionRecord
	for v, val := range r.versions[keyID] {
		records = append(records, model.KeyVersionRecord{KeyID: keyID, Version: v, Value: val})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Version < records[j].Version })
	return records, nil
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
	blob, err := svc.BackupKey(ctx, keyID, userID, uuid.Nil)
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

	blob, err := svc.BackupSecret(ctx, original.ID, owner, vaultA)
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

// TestRestoreSecretPreservesPurgeProtection verifies that a secret backed up
// while purge-protected comes back protected. The repository's Create does
// not write purge_protection, so restore must re-apply the flag explicitly —
// otherwise a backup/restore round-trip silently strips the control.
func TestRestoreSecretPreservesPurgeProtection(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := newStubSecretRepo()
	svc := backup.NewItemBackupService(repo, nil, nil)

	owner := uuid.New()
	vaultID := uuid.New()
	original := &model.Secret{
		ID:              uuid.New(),
		UserID:          owner,
		VaultID:         vaultID,
		Name:            "protected",
		Value:           "v1",
		Version:         1,
		Enabled:         true,
		PurgeProtection: true,
	}
	require.NoError(t, repo.Create(ctx, original))

	blob, err := svc.BackupSecret(ctx, original.ID, owner, vaultID)
	require.NoError(t, err)

	newID := uuid.New()
	require.NoError(t, svc.RestoreSecret(ctx, blob, owner, vaultID, newID))

	restored, err := repo.Read(ctx, newID, model.NewVaultScope(vaultID, owner))
	require.NoError(t, err)
	assert.True(t, restored.PurgeProtection, "restore must preserve the backed-up secret's purge protection")
}

// TestRestoreKeyPreservesPurgeProtection is the key-side twin of
// TestRestoreSecretPreservesPurgeProtection.
func TestRestoreKeyPreservesPurgeProtection(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := newStubKeyRepo()
	svc := backup.NewItemBackupService(nil, repo, nil)

	owner := uuid.New()
	vaultID := uuid.New()
	original := &model.Key{
		ID:              uuid.New(),
		UserID:          owner,
		VaultID:         vaultID,
		Name:            "protected-key",
		Value:           "key-value",
		Type:            model.KeyTypeRSA,
		Enabled:         true,
		PurgeProtection: true,
	}
	require.NoError(t, repo.Create(ctx, original))

	blob, err := svc.BackupKey(ctx, original.ID, owner, vaultID)
	require.NoError(t, err)

	newID := uuid.New()
	require.NoError(t, svc.RestoreKey(ctx, blob, owner, vaultID, newID))

	restored, err := repo.Read(ctx, newID, model.NewAdminScope(owner))
	require.NoError(t, err)
	assert.True(t, restored.PurgeProtection, "restore must preserve the backed-up key's purge protection")
}

// TestRestoreCertificatePreservesPurgeProtection is the certificate-side twin
// of TestRestoreSecretPreservesPurgeProtection.
func TestRestoreCertificatePreservesPurgeProtection(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := newStubCertRepo()
	svc := backup.NewItemBackupService(nil, nil, repo)

	owner := uuid.New()
	vaultID := uuid.New()
	original := &model.Certificate{
		ID:              uuid.New(),
		UserID:          owner,
		VaultID:         vaultID,
		Name:            "protected-cert",
		PurgeProtection: true,
	}
	require.NoError(t, repo.Create(ctx, original))

	blob, err := svc.BackupCertificate(ctx, original.ID, owner, vaultID)
	require.NoError(t, err)

	newID := uuid.New()
	require.NoError(t, svc.RestoreCertificate(ctx, blob, owner, vaultID, newID))

	restored, err := repo.Read(ctx, newID, model.NewAdminScope(owner))
	require.NoError(t, err)
	assert.True(t, restored.PurgeProtection, "restore must preserve the backed-up certificate's purge protection")
}

// TestBackupRestoreKey_CarriesVersionHistory verifies a rotated key's
// key_versions history survives a backup/restore round-trip, and that a
// crypto-relevant old version's material is still present afterward. The
// calling user is deliberately distinct from the key's owner: this is the
// direct regression pin for B28/F2 -- a non-owner backing up a key they
// don't own, but do hold ActionKeysBackup for in the same vault. Under the
// pre-fix code, ListVersionRecords' owner-ID filter would have been passed
// the caller's ID instead of the key's, matched no rows, and silently
// dropped the version history from the blob.
func TestBackupRestoreKey_CarriesVersionHistory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner := uuid.New()
	caller := uuid.New()
	vaultID := uuid.New()
	keyID := uuid.New()

	repo := newStubKeyRepo()
	require.NoError(t, repo.Create(ctx, &model.Key{
		ID: keyID, UserID: owner, VaultID: vaultID, Name: "rotated-key",
		Value: "pem-v2", Type: model.KeyTypeRSA, Enabled: true,
	}))
	require.NoError(t, repo.CreateVersion(ctx, keyID, 1, "pem-v1"))
	require.NoError(t, repo.CreateVersion(ctx, keyID, 2, "pem-v2"))

	svc := backup.NewItemBackupService(nil, repo, nil)

	blob, err := svc.BackupKey(ctx, keyID, caller, vaultID)
	require.NoError(t, err)

	newID := uuid.New()
	require.NoError(t, svc.RestoreKey(ctx, blob, caller, vaultID, newID))

	records, err := repo.ListVersionRecords(ctx, newID)
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, "pem-v1", records[0].Value)
	assert.Equal(t, "pem-v2", records[1].Value)
}

// TestRestoreKey_OldFormatBlob_NoVersionsField verifies a blob encoded
// before this change (no "versions" field on its envelope) still restores
// correctly, with no version history — not an error.
func TestRestoreKey_OldFormatBlob_NoVersionsField(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	owner := uuid.New()
	vaultID := uuid.New()
	keyID := uuid.New()

	repo := newStubKeyRepo()
	require.NoError(t, repo.Create(ctx, &model.Key{
		ID: keyID, UserID: owner, VaultID: vaultID, Name: "never-rotated",
		Value: "pem-v1", Type: model.KeyTypeRSA, Enabled: true,
	}))

	svc := backup.NewItemBackupService(nil, repo, nil)

	// A key with zero key_versions rows produces a blob with an empty/absent
	// "versions" field today, which is exactly the old-format shape.
	blob, err := svc.BackupKey(ctx, keyID, owner, vaultID)
	require.NoError(t, err)

	newID := uuid.New()
	require.NoError(t, svc.RestoreKey(ctx, blob, owner, vaultID, newID))

	records, err := repo.ListVersionRecords(ctx, newID)
	require.NoError(t, err)
	assert.Empty(t, records)
}
