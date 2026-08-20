package keys

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/crypto"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// setJWKTestMasterKey installs a random master key so common.EncryptSecret and
// common.DecryptSecret round-trip inside this test binary.
func setJWKTestMasterKey(t *testing.T) {
	t.Helper()
	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	viper.Set("master_key", base64.StdEncoding.EncodeToString(raw))
}

func newJWKService(repo *mockKeyRepository) KeyService {
	return NewKeyService(KeyServiceConfig{
		KeyRepository: repo,
		Logger:        &logging.Logger{Logger: logrus.New()},
	})
}

// TestGetPublicJWK_RSACurrentVersion is the regression for B34.
//
// api/keys.go called crypto.ExtractPublicComponents(key.Value, ...) directly
// and discarded the error. key.Value is master-key-encrypted, so pem.Decode
// saw base64 ciphertext, returned a nil block, and every response advertised
// n/e/x/y fields that were always empty. Decrypting first is the whole fix, so
// this test asserts non-empty components rather than merely a nil error -- an
// implementation that skipped the decrypt would return empty strings and no
// error, exactly as the buggy handler did.
func TestGetPublicJWK_RSACurrentVersion(t *testing.T) {
	setJWKTestMasterKey(t)

	userID := uuid.New()
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	pemKey, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	stored, err := common.EncryptSecret(pemKey)
	require.NoError(t, err)
	require.NotEqual(t, pemKey, stored, "fixture must be encrypted, or it proves nothing")

	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{
		ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: stored, Enabled: true,
	}, nil)

	jwk, err := newJWKService(repo).GetPublicJWK(context.Background(), keyID, 0, scope)
	require.NoError(t, err)
	require.NotNil(t, jwk)
	assert.NotEmpty(t, jwk.N, "RSA modulus must be populated")
	assert.Equal(t, "AQAB", jwk.E, "65537 is the exponent GenerateRSAKeyPEM uses")
	assert.Empty(t, jwk.X)
	assert.Empty(t, jwk.Y)
}

// TestGetPublicJWK_ECCurrentVersion covers the other branch of
// ExtractPublicComponents: EC keys populate x/y and leave n/e empty.
func TestGetPublicJWK_ECCurrentVersion(t *testing.T) {
	setJWKTestMasterKey(t)

	userID := uuid.New()
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	pemKey, err := crypto.GenerateECDSAKeyPEM("P-256")
	require.NoError(t, err)
	stored, err := common.EncryptSecret(pemKey)
	require.NoError(t, err)

	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{
		ID: keyID, UserID: userID, Type: model.KeyTypeECDSA, Value: stored, Enabled: true,
	}, nil)

	jwk, err := newJWKService(repo).GetPublicJWK(context.Background(), keyID, 0, scope)
	require.NoError(t, err)
	assert.NotEmpty(t, jwk.X)
	assert.NotEmpty(t, jwk.Y)
	assert.Empty(t, jwk.N)
	assert.Empty(t, jwk.E)
}

// TestGetPublicJWK_ArchivedVersion pins that a non-current version reads its
// material from key_versions rather than the key row.
func TestGetPublicJWK_ArchivedVersion(t *testing.T) {
	setJWKTestMasterKey(t)

	userID := uuid.New()
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	currentPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	currentStored, err := common.EncryptSecret(currentPEM)
	require.NoError(t, err)

	archivedPEM, err := crypto.GenerateRSAKeyPEM(2048)
	require.NoError(t, err)
	archivedStored, err := common.EncryptSecret(archivedPEM)
	require.NoError(t, err)

	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{
		ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: currentStored, Enabled: true,
	}, nil)
	repo.On("CurrentVersion", mock.Anything, keyID).Return(3, nil)
	repo.On("ReadVersionValue", mock.Anything, keyID, 1).Return(archivedStored, nil)

	svc := newJWKService(repo)

	archived, err := svc.GetPublicJWK(context.Background(), keyID, 1, scope)
	require.NoError(t, err)
	current, err := svc.GetPublicJWK(context.Background(), keyID, 0, scope)
	require.NoError(t, err)

	assert.NotEmpty(t, archived.N)
	assert.NotEqual(t, current.N, archived.N,
		"version 1 must return the archived key's modulus, not the current one's")
	repo.AssertExpectations(t)
}

// TestGetPublicJWK_HSMKeyIsEmptyNotAnError pins the documented HSM contract: a
// key whose material never left the token has no public components to return,
// and that is a normal result rather than a 500.
func TestGetPublicJWK_HSMKeyIsEmptyNotAnError(t *testing.T) {
	setJWKTestMasterKey(t)

	userID := uuid.New()
	keyID := uuid.New()
	scope := model.NewOwnerScope(uuid.Nil, userID)

	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, scope).Return(&model.Key{
		ID: keyID, UserID: userID, Type: model.KeyTypeRSA, Value: "pkcs11:some-label", Enabled: true,
	}, nil)

	jwk, err := newJWKService(repo).GetPublicJWK(context.Background(), keyID, 0, scope)
	require.NoError(t, err, "an HSM key is not an error case")
	require.NotNil(t, jwk)
	assert.Equal(t, model.PublicJWK{}, *jwk)
}

// TestGetPublicJWK_UnauthorizedScopeIsRefused pins that the scoped GetKey read
// is the authorization gate: no scope, no components.
func TestGetPublicJWK_UnauthorizedScopeIsRefused(t *testing.T) {
	setJWKTestMasterKey(t)

	userID := uuid.New()
	keyID := uuid.New()
	scope := model.NewVaultScope(uuid.New(), userID)

	repo := &mockKeyRepository{}
	repo.On("Read", mock.Anything, keyID, scope).Return(nil, sql.ErrNoRows)

	jwk, err := newJWKService(repo).GetPublicJWK(context.Background(), keyID, 0, scope)
	require.Error(t, err)
	assert.Nil(t, jwk)
}
