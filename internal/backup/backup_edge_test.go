package backup_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/backup"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// -- certificate stub -------------------------------------------------------

type stubCertRepo struct {
	certs map[uuid.UUID]*model.Certificate
	err   error
}

func newStubCertRepo() *stubCertRepo {
	return &stubCertRepo{certs: make(map[uuid.UUID]*model.Certificate)}
}

func (r *stubCertRepo) Create(_ context.Context, c *model.Certificate) error {
	if r.err != nil {
		return r.err
	}
	cp := *c
	r.certs[c.ID] = &cp
	return nil
}

func (r *stubCertRepo) Read(_ context.Context, id uuid.UUID) (*model.Certificate, error) {
	if r.err != nil {
		return nil, r.err
	}
	c, ok := r.certs[id]
	if !ok {
		return nil, fmt.Errorf("cert not found")
	}
	cp := *c
	return &cp, nil
}

func (r *stubCertRepo) ReadScoped(_ context.Context, id uuid.UUID, _ model.Scope) (*model.Certificate, error) {
	if r.err != nil {
		return nil, r.err
	}
	c, ok := r.certs[id]
	if !ok {
		return nil, fmt.Errorf("cert not found")
	}
	cp := *c
	return &cp, nil
}

func (r *stubCertRepo) UpdateScoped(_ context.Context, _ *model.Certificate, _ model.Scope) error {
	return r.err
}

func (r *stubCertRepo) ListScoped(_ context.Context, _ model.Scope, _ repositories.CertificateFilter) ([]model.Certificate, error) {
	return nil, r.err
}

func (r *stubCertRepo) Update(_ context.Context, _ *model.Certificate) error      { return r.err }
func (r *stubCertRepo) Delete(_ context.Context, _ uuid.UUID) error               { return r.err }
func (r *stubCertRepo) Revoke(_ context.Context, _ uuid.UUID, _, _ string) error  { return r.err }
func (r *stubCertRepo) SoftDelete(_ context.Context, _ uuid.UUID) error           { return r.err }
func (r *stubCertRepo) RecoverCertificate(_ context.Context, _ uuid.UUID) error   { return r.err }
func (r *stubCertRepo) PurgeCertificate(_ context.Context, _ uuid.UUID) error     { return r.err }
func (r *stubCertRepo) SetPurgeProtection(_ context.Context, _ uuid.UUID, _ bool) error {
	return r.err
}
func (r *stubCertRepo) ListByUser(_ context.Context, _ uuid.UUID, _ []string) ([]model.Certificate, error) {
	return nil, r.err
}
func (r *stubCertRepo) ListRevoked(_ context.Context, _ uuid.UUID) ([]model.RevokedCertificate, error) {
	return nil, r.err
}
func (r *stubCertRepo) ListSoftDeleted(_ context.Context, _ uuid.UUID) ([]*model.Certificate, error) {
	return nil, r.err
}
func (r *stubCertRepo) ListAll(_ context.Context) ([]model.Certificate, error) { return nil, r.err }
func (r *stubCertRepo) ListInVault(_ context.Context, _ uuid.UUID, _ []string) ([]model.Certificate, error) {
	return nil, r.err
}
func (r *stubCertRepo) ReadInVault(_ context.Context, _, _ uuid.UUID) (*model.Certificate, error) {
	return nil, r.err
}
func (r *stubCertRepo) SoftDeleteVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return r.err
}
func (r *stubCertRepo) RecoverVaultContents(_ context.Context, _ uuid.UUID, _ time.Time) error {
	return r.err
}

// -- erroring stubs for secret/key repos ------------------------------------

type errSecretRepo struct{ *stubSecretRepo }

func newErrSecretRepo() *errSecretRepo { return &errSecretRepo{newStubSecretRepo()} }

func (r *errSecretRepo) Read(_ context.Context, _ uuid.UUID, _ model.Scope) (*model.Secret, error) {
	return nil, errors.New("db failure")
}

func (r *errSecretRepo) Create(_ context.Context, _ *model.Secret) error {
	return errors.New("create failure")
}

type errKeyRepo struct{ *stubKeyRepo }

func newErrKeyRepo() *errKeyRepo { return &errKeyRepo{newStubKeyRepo()} }

func (r *errKeyRepo) Read(_ context.Context, _ uuid.UUID) (*model.Key, error) {
	return nil, errors.New("db failure")
}

func (r *errKeyRepo) Create(_ context.Context, _ *model.Key) error {
	return errors.New("create failure")
}

// -- BackupKey / RestoreKey -------------------------------------------------

func TestBackupKeyForbidden(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	otherID := uuid.New()
	keyID := uuid.New()

	kr := newStubKeyRepo()
	require.NoError(t, kr.Create(ctx, &model.Key{
		ID: keyID, UserID: ownerID, Name: "k", Value: "v", Type: model.KeyTypeRSA, Enabled: true,
	}))

	svc := backup.NewItemBackupService(nil, kr, nil)

	_, err := svc.BackupKey(ctx, keyID, otherID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "forbidden")
}

func TestBackupKeyRepoError(t *testing.T) {
	t.Parallel()

	svc := backup.NewItemBackupService(nil, newErrKeyRepo(), nil)
	_, err := svc.BackupKey(context.Background(), uuid.New(), uuid.New())
	require.Error(t, err)
}

func TestRestoreKeySuccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	keyID := uuid.New()

	kr := newStubKeyRepo()
	require.NoError(t, kr.Create(ctx, &model.Key{
		ID: keyID, UserID: ownerID, Name: "k", Value: "v", Type: model.KeyTypeRSA, Enabled: true,
	}))

	svc := backup.NewItemBackupService(nil, kr, nil)

	blob, err := svc.BackupKey(ctx, keyID, ownerID)
	require.NoError(t, err)

	require.NoError(t, kr.Delete(ctx, keyID))

	newID := uuid.New()
	require.NoError(t, svc.RestoreKey(ctx, blob, ownerID, newID))

	restored, err := kr.Read(ctx, newID)
	require.NoError(t, err)
	require.Equal(t, "k", restored.Name)
}

func TestRestoreKeyBlobError(t *testing.T) {
	t.Parallel()

	svc := backup.NewItemBackupService(nil, newStubKeyRepo(), nil)
	err := svc.RestoreKey(context.Background(), "!!!not-base64!!!", uuid.New(), uuid.New())
	require.Error(t, err)
	require.True(t, errors.Is(err, backup.ErrInvalidBlob))
}

func TestRestoreKeyTypeMismatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	sr := newStubSecretRepo()
	require.NoError(t, sr.Create(ctx, &model.Secret{
		ID: secretID, UserID: userID, Name: "s", Value: "v", Version: 1, Enabled: true,
	}))

	svc := backup.NewItemBackupService(sr, newStubKeyRepo(), nil)

	// A secret blob must not restore as a key.
	blob, err := svc.BackupSecret(ctx, secretID, userID)
	require.NoError(t, err)

	err = svc.RestoreKey(ctx, blob, userID, uuid.New())
	require.Error(t, err)
	require.True(t, errors.Is(err, backup.ErrInvalidBlob))
}

// -- BackupCertificate / RestoreCertificate ---------------------------------

func TestBackupCertificateSuccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	certID := uuid.New()

	cr := newStubCertRepo()
	cr.certs[certID] = &model.Certificate{
		ID: certID, UserID: ownerID, Name: "my-cert",
	}

	svc := backup.NewItemBackupService(nil, nil, cr)

	blob, err := svc.BackupCertificate(ctx, certID, ownerID)
	require.NoError(t, err)
	require.NotEmpty(t, blob)
}

func TestBackupCertificateForbidden(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	otherID := uuid.New()
	certID := uuid.New()

	cr := newStubCertRepo()
	cr.certs[certID] = &model.Certificate{
		ID: certID, UserID: ownerID, Name: "cert",
	}

	svc := backup.NewItemBackupService(nil, nil, cr)

	_, err := svc.BackupCertificate(ctx, certID, otherID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "forbidden")
}

func TestBackupCertificateRepoError(t *testing.T) {
	t.Parallel()

	cr := newStubCertRepo()
	cr.err = errors.New("db failure")

	svc := backup.NewItemBackupService(nil, nil, cr)
	_, err := svc.BackupCertificate(context.Background(), uuid.New(), uuid.New())
	require.Error(t, err)
}

func TestRestoreCertificateSuccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ownerID := uuid.New()
	certID := uuid.New()

	cr := newStubCertRepo()
	cr.certs[certID] = &model.Certificate{
		ID: certID, UserID: ownerID, Name: "my-cert",
	}

	svc := backup.NewItemBackupService(nil, nil, cr)

	blob, err := svc.BackupCertificate(ctx, certID, ownerID)
	require.NoError(t, err)

	delete(cr.certs, certID)

	newID := uuid.New()
	require.NoError(t, svc.RestoreCertificate(ctx, blob, ownerID, newID))

	restored, err := cr.Read(ctx, newID)
	require.NoError(t, err)
	require.Equal(t, "my-cert", restored.Name)
}

func TestRestoreCertificateBlobError(t *testing.T) {
	t.Parallel()

	svc := backup.NewItemBackupService(nil, nil, newStubCertRepo())
	err := svc.RestoreCertificate(context.Background(), "!!!bad!!!", uuid.New(), uuid.New())
	require.Error(t, err)
	require.True(t, errors.Is(err, backup.ErrInvalidBlob))
}

func TestRestoreCertificateTypeMismatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	certID := uuid.New()

	cr := newStubCertRepo()
	cr.certs[certID] = &model.Certificate{
		ID: certID, UserID: userID, Name: "c",
	}

	svc := backup.NewItemBackupService(nil, nil, cr)

	// Build a cert blob then attempt to restore it as a secret.
	blob, err := svc.BackupCertificate(ctx, certID, userID)
	require.NoError(t, err)

	err = svc.RestoreSecret(ctx, blob, userID, uuid.New())
	require.Error(t, err)
	require.True(t, errors.Is(err, backup.ErrInvalidBlob))
}

// -- BackupSecret edge paths ------------------------------------------------

func TestBackupSecretReadError(t *testing.T) {
	t.Parallel()

	svc := backup.NewItemBackupService(newErrSecretRepo(), nil, nil)
	_, err := svc.BackupSecret(context.Background(), uuid.New(), uuid.New())
	require.Error(t, err)
}

func TestRestoreSecretCreateError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := uuid.New()
	secretID := uuid.New()

	// Build blob via a working repo.
	good := newStubSecretRepo()
	require.NoError(t, good.Create(ctx, &model.Secret{
		ID: secretID, UserID: userID, Name: "s", Value: "v", Version: 1, Enabled: true,
	}))

	goodSvc := backup.NewItemBackupService(good, nil, nil)
	blob, err := goodSvc.BackupSecret(ctx, secretID, userID)
	require.NoError(t, err)

	// Restore into a failing repo.
	badSvc := backup.NewItemBackupService(newErrSecretRepo(), nil, nil)
	err = badSvc.RestoreSecret(ctx, blob, userID, uuid.New())
	require.Error(t, err)
}
