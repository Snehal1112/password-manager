package keys_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	"rocketvault/internal/services/keys"
)

// setupWrapTestMasterKey sets a deterministic 32-byte master key for encryption tests.
func setupWrapTestMasterKey() {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	viper.Set("master_key", base64.StdEncoding.EncodeToString(key))
}

// generateTestRSAPEM creates a 2048-bit RSA private key in PEM format for tests.
func generateTestRSAPEM(t *testing.T) string {
	t.Helper()
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pk),
	}))
}

// mockKeyRepoForWrap is a minimal mock of KeyRepositoryInterface for wrap tests.
type mockKeyRepoForWrap struct{ mock.Mock }

func (m *mockKeyRepoForWrap) Read(ctx context.Context, id uuid.UUID) (*domain.Key, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Key), args.Error(1)
}
func (m *mockKeyRepoForWrap) Create(ctx context.Context, k *domain.Key) error { return nil }
func (m *mockKeyRepoForWrap) Update(ctx context.Context, k *domain.Key) error { return nil }
func (m *mockKeyRepoForWrap) Delete(ctx context.Context, id uuid.UUID) error  { return nil }
func (m *mockKeyRepoForWrap) ListByUser(ctx context.Context, userID *uuid.UUID, keyType string, tags []string) ([]domain.Key, error) {
	return nil, nil
}
func (m *mockKeyRepoForWrap) UpdateRevocationStatus(ctx context.Context, id uuid.UUID, revoked bool) error {
	return nil
}
func (m *mockKeyRepoForWrap) SoftDelete(ctx context.Context, id uuid.UUID) error  { return nil }
func (m *mockKeyRepoForWrap) RecoverKey(ctx context.Context, id uuid.UUID) error  { return nil }
func (m *mockKeyRepoForWrap) PurgeKey(ctx context.Context, id uuid.UUID) error    { return nil }
func (m *mockKeyRepoForWrap) SetPurgeProtection(ctx context.Context, id uuid.UUID, enabled bool) error {
	return nil
}
func (m *mockKeyRepoForWrap) ListSoftDeleted(ctx context.Context, userID uuid.UUID) ([]*domain.Key, error) {
	return nil, nil
}

func TestWrapAndUnwrapKey(t *testing.T) {
	setupWrapTestMasterKey()
	privateKeyPEM := generateTestRSAPEM(t)
	encryptedPEM, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()
	vaultKey := &domain.Key{
		ID:      keyID,
		UserID:  userID,
		Type:    "RSA",
		Value:   encryptedPEM,
		Revoked: false,
	}

	repo := &mockKeyRepoForWrap{}
	repo.On("Read", mock.Anything, keyID).Return(vaultKey, nil)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	plaintext := []byte("super-secret-dek-32-bytes-padded")

	wrapResult, err := svc.WrapKey(context.Background(), keys.WrapKeyRequest{
		KeyID:        keyID,
		UserID:       userID,
		PlaintextKey: plaintext,
		Algorithm:    "RSA-OAEP",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, wrapResult.WrappedKey)
	assert.Equal(t, "RSA-OAEP", wrapResult.Algorithm)

	unwrapResult, err := svc.UnwrapKey(context.Background(), keys.UnwrapKeyRequest{
		KeyID:      keyID,
		UserID:     userID,
		WrappedKey: wrapResult.WrappedKey,
		Algorithm:  "RSA-OAEP",
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, unwrapResult.PlaintextKey)
}

func TestWrapKeyForbiddenForWrongUser(t *testing.T) {
	setupWrapTestMasterKey()
	privateKeyPEM := generateTestRSAPEM(t)
	encryptedPEM, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	ownerID := uuid.New()
	callerID := uuid.New()
	keyID := uuid.New()

	repo := &mockKeyRepoForWrap{}
	repo.On("Read", mock.Anything, keyID).Return(&domain.Key{
		ID: keyID, UserID: ownerID, Type: "RSA", Value: encryptedPEM,
	}, nil)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	_, err = svc.WrapKey(context.Background(), keys.WrapKeyRequest{
		KeyID:        keyID,
		UserID:       callerID,
		PlaintextKey: []byte("dek"),
		Algorithm:    "RSA-OAEP",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestWrapKeyRejectsUnsupportedAlgorithm(t *testing.T) {
	setupWrapTestMasterKey()
	privateKeyPEM := generateTestRSAPEM(t)
	encryptedPEM, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()

	repo := &mockKeyRepoForWrap{}
	repo.On("Read", mock.Anything, keyID).Return(&domain.Key{
		ID: keyID, UserID: userID, Type: "RSA", Value: encryptedPEM,
	}, nil)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	_, err = svc.WrapKey(context.Background(), keys.WrapKeyRequest{
		KeyID:        keyID,
		UserID:       userID,
		PlaintextKey: []byte("dek"),
		Algorithm:    "ECDH-ES",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}
