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
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories/mocks"
	"rocketvault/internal/services/keys"
	"rocketvault/model"
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

func TestWrapAndUnwrapKey(t *testing.T) {
	setupWrapTestMasterKey()
	privateKeyPEM := generateTestRSAPEM(t)
	encryptedPEM, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()
	vaultKey := &model.Key{
		ID:      keyID,
		UserID:  userID,
		Type:    "RSA",
		Value:   encryptedPEM,
		Revoked: false,
		Enabled: true,
	}

	repo := mocks.NewMockKeyRepositoryInterface(t)
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

func TestWrapAndUnwrapKey_OAEP256(t *testing.T) {
	setupWrapTestMasterKey()
	privateKeyPEM := generateTestRSAPEM(t)
	encryptedPEM, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()
	vaultKey := &model.Key{
		ID: keyID, UserID: userID, Type: "RSA", Value: encryptedPEM, Revoked: false, Enabled: true,
	}

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID).Return(vaultKey, nil)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	dek := []byte("32-byte-data-encryption-key-here")

	wrapResult, err := svc.WrapKey(context.Background(), keys.WrapKeyRequest{
		KeyID: keyID, UserID: userID, PlaintextKey: dek, Algorithm: "RSA-OAEP-256",
	})
	require.NoError(t, err)
	assert.Equal(t, "RSA-OAEP-256", wrapResult.Algorithm)

	unwrapResult, err := svc.UnwrapKey(context.Background(), keys.UnwrapKeyRequest{
		KeyID: keyID, UserID: userID, WrappedKey: wrapResult.WrappedKey, Algorithm: "RSA-OAEP-256",
	})
	require.NoError(t, err)
	assert.Equal(t, dek, unwrapResult.PlaintextKey)
}

func TestWrapKeyForbiddenForWrongUser(t *testing.T) {
	setupWrapTestMasterKey()
	privateKeyPEM := generateTestRSAPEM(t)
	encryptedPEM, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	ownerID := uuid.New()
	callerID := uuid.New()
	keyID := uuid.New()

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID).Return(&model.Key{
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

	userID := uuid.New()
	keyID := uuid.New()

	// The algorithm allowlist is checked before the key is loaded, so the
	// repository is never called for this path; no expectation is set up.
	repo := mocks.NewMockKeyRepositoryInterface(t)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	_, err := svc.WrapKey(context.Background(), keys.WrapKeyRequest{
		KeyID:        keyID,
		UserID:       userID,
		PlaintextKey: []byte("dek"),
		Algorithm:    "ECDH-ES",
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, keys.ErrUnsupportedAlgorithm)
}

func TestWrapKey_AESKWAlgorithmNotRejectedByAllowlist(t *testing.T) {
	setupWrapTestMasterKey()
	privateKeyPEM := generateTestRSAPEM(t)
	encryptedPEM, err := common.EncryptSecret(privateKeyPEM)
	require.NoError(t, err)

	userID := uuid.New()
	keyID := uuid.New()

	repo := mocks.NewMockKeyRepositoryInterface(t)
	repo.On("Read", mock.Anything, keyID).Return(&model.Key{
		ID: keyID, UserID: userID, Type: "RSA", Value: encryptedPEM,
	}, nil)

	svc := keys.NewCryptoService(keys.CryptoServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})

	_, err = svc.WrapKey(context.Background(), keys.WrapKeyRequest{
		UserID:       userID,
		KeyID:        keyID,
		Algorithm:    "A256KW",
		PlaintextKey: []byte("test-key-material"),
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "unsupported algorithm",
		"A256KW must pass the algorithm allowlist")
}
