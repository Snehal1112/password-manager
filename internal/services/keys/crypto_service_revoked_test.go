package keys_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories/mocks"
	"rocketvault/internal/services/keys"
	"rocketvault/model"
)

// newRevokedKeyCryptoSvc builds a CryptoService backed by a mock repo that
// returns a revoked key for any Read call. No master key setup needed
// because the revoked check fires before any crypto operation is attempted.
func newRevokedKeyCryptoSvc(t *testing.T, keyID, userID uuid.UUID) keys.CryptoService {
	t.Helper()

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID, model.NewOwnerScope(uuid.Nil, userID)).Return(&model.Key{
		ID:      keyID,
		UserID:  userID,
		Type:    "RSA",
		Value:   "irrelevant", // crypto path is never reached for revoked keys
		Revoked: true,
	}, nil)

	return keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})
}

// TestVerify_RejectsRevokedKey ensures Verify returns an error mentioning "revoked".
func TestVerify_RejectsRevokedKey(t *testing.T) {
	t.Parallel()
	keyID := uuid.New()
	userID := uuid.New()
	svc := newRevokedKeyCryptoSvc(t, keyID, userID)

	_, err := svc.Verify(context.Background(), keys.VerifyRequest{
		KeyID:     keyID,
		UserID:    userID,
		Scope:     model.NewOwnerScope(uuid.Nil, userID),
		Data:      []byte("hello"),
		Signature: []byte("sig"),
	})
	require.ErrorContains(t, err, "revoked")
}

// TestDecrypt_RejectsRevokedKey ensures Decrypt returns an error mentioning "revoked".
func TestDecrypt_RejectsRevokedKey(t *testing.T) {
	t.Parallel()
	keyID := uuid.New()
	userID := uuid.New()
	svc := newRevokedKeyCryptoSvc(t, keyID, userID)

	_, err := svc.Decrypt(context.Background(), keys.DecryptRequest{
		KeyID:      keyID,
		UserID:     userID,
		Scope:      model.NewOwnerScope(uuid.Nil, userID),
		Ciphertext: []byte("ciphertext"),
	})
	require.ErrorContains(t, err, "revoked")
}
