package repositories_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// TestSecretRepositoryFinalAPIShape is a compile-time gate: it fails to build
// while any legacy secret method still exists on the interface, and while the
// scoped methods still carry the transitional Scoped suffix.
func TestSecretRepositoryFinalAPIShape(t *testing.T) {
	var repo repositories.SecretRepositoryInterface
	if repo != nil {
		ctx := context.Background()
		_, _ = repo.Read(ctx, uuid.New(), model.NewAdminScope(uuid.Nil))
		_ = repo.Update(ctx, &model.Secret{}, model.NewAdminScope(uuid.Nil))
		_, _ = repo.List(ctx, model.NewAdminScope(uuid.Nil), repositories.SecretFilter{})
	}
}

// TestKeyRepositoryFinalAPIShape is a compile-time gate for the key repository.
func TestKeyRepositoryFinalAPIShape(t *testing.T) {
	var repo repositories.KeyRepositoryInterface
	if repo != nil {
		ctx := context.Background()
		_, _ = repo.Read(ctx, uuid.New(), model.NewAdminScope(uuid.Nil))
		_ = repo.Update(ctx, &model.Key{}, model.NewAdminScope(uuid.Nil))
		_, _ = repo.List(ctx, model.NewAdminScope(uuid.Nil), repositories.KeyFilter{})
	}
}

// TestCertificateRepositoryFinalAPIShape is a compile-time gate for the
// certificate repository.
func TestCertificateRepositoryFinalAPIShape(t *testing.T) {
	var repo repositories.CertificateRepositoryInterface
	if repo != nil {
		ctx := context.Background()
		_, _ = repo.Read(ctx, uuid.New(), model.NewAdminScope(uuid.Nil))
		_ = repo.Update(ctx, &model.Certificate{}, model.NewAdminScope(uuid.Nil))
		_, _ = repo.List(ctx, model.NewAdminScope(uuid.Nil), repositories.CertificateFilter{})
	}
}
