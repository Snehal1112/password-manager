package retry

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/viper"

	"rocketvault/internal/repositories"
	"rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// purgeProtectedSecretService always reports the secret as purge-protected.
// It embeds the interface (left nil) so only PurgeSecret has real behavior;
// any other call panics, which is the correct failure mode here.
type purgeProtectedSecretService struct {
	secrets.SecretService
}

func (s *purgeProtectedSecretService) PurgeSecret(_ context.Context, _ uuid.UUID, _ model.Scope) error {
	return repositories.ErrSecretPurgeProtected
}

// TestPurgeSecretSentinelSurvivesRetryWiring is the composition-level guard for
// purge protection: it exercises the real retry service built from default
// config, which is what production uses whenever retry.database.enabled is
// true. The retry layer classifies the purge-protection sentinel as
// non-retryable and wraps it; if that wrap ever loses the error chain again,
// api.writeSecretError stops recognising the sentinel and a blocked purge
// silently regresses from HTTP 403 to 500. The wrapped message alone is not
// enough to catch this — the old, broken %v wrap produced a byte-identical
// error string and only errors.Is could tell the difference.
func TestPurgeSecretSentinelSurvivesRetryWiring(t *testing.T) {
	retryService, err := NewRetryService(viper.New())
	if err != nil {
		t.Fatalf("failed to build retry service: %v", err)
	}

	svc := NewRetrySecretService(&purgeProtectedSecretService{}, retryService)

	err = svc.PurgeSecret(context.Background(), uuid.New(), model.NewVaultScope(uuid.New(), uuid.New()))
	if !errors.Is(err, repositories.ErrSecretPurgeProtected) {
		t.Fatalf("purge-protection sentinel did not survive the retry layer: %v", err)
	}
}
