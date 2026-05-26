/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

// Package api — unit tests for sign/verify/encrypt/decrypt key handlers.
package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/app"
	"rocketvault/internal/cache"
	"rocketvault/internal/crypto"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/internal/signing"
	authServices "rocketvault/internal/services/auth"
	authzServices "rocketvault/internal/services/authorization"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	oauth2Services "rocketvault/internal/services/oauth2"
	retryServices "rocketvault/internal/services/retry"
	secretServices "rocketvault/internal/services/secrets"
	userServices "rocketvault/internal/services/users"
)

// --- minimal mock crypto service ---

// stubCryptoSvc is a minimal stub of keyServices.CryptoService for handler tests.
type stubCryptoSvc struct {
	signFn    func(ctx context.Context, req keyServices.SignRequest) (*keyServices.SignResult, error)
	verifyFn  func(ctx context.Context, req keyServices.VerifyRequest) (*keyServices.VerifyResult, error)
	encryptFn func(ctx context.Context, req keyServices.EncryptRequest) (*keyServices.EncryptResult, error)
	decryptFn func(ctx context.Context, req keyServices.DecryptRequest) (*keyServices.DecryptResult, error)
}

func (s *stubCryptoSvc) Sign(ctx context.Context, req keyServices.SignRequest) (*keyServices.SignResult, error) {
	return s.signFn(ctx, req)
}
func (s *stubCryptoSvc) Verify(ctx context.Context, req keyServices.VerifyRequest) (*keyServices.VerifyResult, error) {
	return s.verifyFn(ctx, req)
}
func (s *stubCryptoSvc) Encrypt(ctx context.Context, req keyServices.EncryptRequest) (*keyServices.EncryptResult, error) {
	return s.encryptFn(ctx, req)
}
func (s *stubCryptoSvc) Decrypt(ctx context.Context, req keyServices.DecryptRequest) (*keyServices.DecryptResult, error) {
	return s.decryptFn(ctx, req)
}
func (s *stubCryptoSvc) WrapKey(ctx context.Context, req keyServices.WrapKeyRequest) (*keyServices.WrapKeyResult, error) {
	return nil, errors.New("not implemented")
}
func (s *stubCryptoSvc) UnwrapKey(ctx context.Context, req keyServices.UnwrapKeyRequest) (*keyServices.UnwrapKeyResult, error) {
	return nil, errors.New("not implemented")
}

// --- minimal mock service container ---

// cryptoTestContainer satisfies container.ServiceContainerInterface using a stub
// crypto service. Methods not exercised by the handlers under test panic.
type cryptoTestContainer struct {
	svc keyServices.CryptoService
}

func (c *cryptoTestContainer) GetCryptoService() keyServices.CryptoService { return c.svc }

// The remaining stubs satisfy the interface but are not called by the four handlers.
func (c *cryptoTestContainer) GetRBACService() authzServices.RBACService {
	panic("unexpected call: GetRBACService")
}
func (c *cryptoTestContainer) GetUserRepository() repositories.UserRepositoryInterface {
	panic("unexpected call: GetUserRepository")
}
func (c *cryptoTestContainer) GetSecretRepository() repositories.SecretRepositoryInterface {
	panic("unexpected call: GetSecretRepository")
}
func (c *cryptoTestContainer) GetRotationRepository() repositories.RotationPolicyRepositoryInterface {
	panic("unexpected call: GetRotationRepository")
}
func (c *cryptoTestContainer) GetVersionRepository() repositories.SecretVersionRepositoryInterface {
	panic("unexpected call: GetVersionRepository")
}
func (c *cryptoTestContainer) GetKeyRepository() repositories.KeyRepositoryInterface {
	panic("unexpected call: GetKeyRepository")
}
func (c *cryptoTestContainer) GetCertificateRepository() repositories.CertificateRepositoryInterface {
	panic("unexpected call: GetCertificateRepository")
}
func (c *cryptoTestContainer) GetSessionRepository() repositories.SessionRepositoryInterface {
	panic("unexpected call: GetSessionRepository")
}
func (c *cryptoTestContainer) GetPasswordService() authServices.PasswordService {
	panic("unexpected call: GetPasswordService")
}
func (c *cryptoTestContainer) GetTOTPService() authServices.TOTPService {
	panic("unexpected call: GetTOTPService")
}
func (c *cryptoTestContainer) GetJWTService() authServices.JWTService {
	panic("unexpected call: GetJWTService")
}
func (c *cryptoTestContainer) GetAuthenticationService() authServices.AuthenticationService {
	panic("unexpected call: GetAuthenticationService")
}
func (c *cryptoTestContainer) GetAccessPolicyRepository() repositories.AccessPolicyRepositoryInterface {
	panic("unexpected call: GetAccessPolicyRepository")
}
func (c *cryptoTestContainer) GetAccessPolicyService() authzServices.AccessPolicyService {
	panic("unexpected call: GetAccessPolicyService")
}
func (c *cryptoTestContainer) GetOAuth2ClientRepository() repositories.OAuth2ClientRepositoryInterface {
	panic("unexpected call: GetOAuth2ClientRepository")
}
func (c *cryptoTestContainer) GetOAuth2Service() oauth2Services.OAuth2Service {
	panic("unexpected call: GetOAuth2Service")
}
func (c *cryptoTestContainer) GetUserService() userServices.UserService {
	panic("unexpected call: GetUserService")
}
func (c *cryptoTestContainer) GetSecretService() secretServices.SecretService {
	panic("unexpected call: GetSecretService")
}
func (c *cryptoTestContainer) GetKeyService() keyServices.KeyService {
	panic("unexpected call: GetKeyService")
}
func (c *cryptoTestContainer) GetCertificateService() certServices.CertificateService {
	panic("unexpected call: GetCertificateService")
}
func (c *cryptoTestContainer) GetCertificateRenewalService() certServices.CertificateRenewalService {
	panic("unexpected call: GetCertificateRenewalService")
}
func (c *cryptoTestContainer) GetCryptographyService() secretServices.CryptographyService {
	panic("unexpected call: GetCryptographyService")
}
func (c *cryptoTestContainer) GetVersioningService() secretServices.VersioningServiceInterface {
	panic("unexpected call: GetVersioningService")
}
func (c *cryptoTestContainer) GetTagService() secretServices.TagService {
	panic("unexpected call: GetTagService")
}
func (c *cryptoTestContainer) GetRotationService() secretServices.RotationServiceInterface {
	panic("unexpected call: GetRotationService")
}
func (c *cryptoTestContainer) GetSchedulerService() secretServices.SchedulerServiceInterface {
	panic("unexpected call: GetSchedulerService")
}
func (c *cryptoTestContainer) GetDatabase() *sql.DB {
	panic("unexpected call: GetDatabase")
}
func (c *cryptoTestContainer) GetLogger() *logging.Logger {
	panic("unexpected call: GetLogger")
}
func (c *cryptoTestContainer) GetSecretCache() *cache.SecretCache {
	panic("unexpected call: GetSecretCache")
}
func (c *cryptoTestContainer) GetCacheConfig() *cache.CacheConfig {
	panic("unexpected call: GetCacheConfig")
}
func (c *cryptoTestContainer) GetCachedSecretService() secretServices.SecretService {
	panic("unexpected call: GetCachedSecretService")
}
func (c *cryptoTestContainer) GetRetryService() retryServices.RetryService {
	panic("unexpected call: GetRetryService")
}
func (c *cryptoTestContainer) GetSigningProvider() signing.SigningKeyProvider { return nil }
func (c *cryptoTestContainer) Close() error                                   { return nil }

// --- helpers ---

const testKeyIDStr = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
const testUserIDStr = "b2c3d4e5-f6a7-8901-bcde-f12345678901"

// newCryptoContext builds a minimal Context wired to the given stub.
func newCryptoContext(svc keyServices.CryptoService) *Context {
	a := &app.App{ServiceContainer: &cryptoTestContainer{svc: svc}}
	return &Context{
		App: a,
		Claims: jwt.MapClaims{
			"user_id": testUserIDStr,
		},
		Params: &ApiParams{KeyID: testKeyIDStr},
	}
}

// jsonBody encodes v as JSON and returns an io.ReadCloser.
func jsonBody(t *testing.T, v any) io.ReadCloser {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return io.NopCloser(bytes.NewReader(b))
}

// --- signKey tests ---

func TestSignKey_Success(t *testing.T) {
	sig := []byte("fake-signature-bytes")
	svc := &stubCryptoSvc{
		signFn: func(_ context.Context, req keyServices.SignRequest) (*keyServices.SignResult, error) {
			assert.Equal(t, testKeyIDStr, req.KeyID.String())
			assert.Equal(t, testUserIDStr, req.UserID.String())
			assert.Equal(t, []byte("hello"), req.Data)
			assert.Equal(t, crypto.SignatureAlgorithm("RS256"), req.Algorithm)
			return &keyServices.SignResult{
				Signature: sig,
				Algorithm: crypto.SignatureAlgorithm("RS256"),
			}, nil
		},
	}

	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value":     base64.StdEncoding.EncodeToString([]byte("hello")),
		"algorithm": "RS256",
	}))

	signKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	require.Equal(t, http.StatusOK, w.Code)
	var resp SignKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, testKeyIDStr, resp.KeyID)
	assert.Equal(t, "RS256", resp.Algorithm)
	assert.Equal(t, base64.StdEncoding.EncodeToString(sig), resp.Value)
}

func TestSignKey_MissingValue_Returns400(t *testing.T) {
	c := newCryptoContext(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{"algorithm": "RS256"}))

	signKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignKey_InvalidBase64_Returns400(t *testing.T) {
	c := newCryptoContext(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value":     "not-valid-base64!!!",
		"algorithm": "RS256",
	}))

	signKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSignKey_KeyNotFound_Returns404(t *testing.T) {
	svc := &stubCryptoSvc{
		signFn: func(_ context.Context, _ keyServices.SignRequest) (*keyServices.SignResult, error) {
			return nil, fmt.Errorf("key not found: %w", errors.New("sql: no rows"))
		},
	}

	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value": base64.StdEncoding.EncodeToString([]byte("data")),
	}))

	signKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSignKey_Forbidden_Returns403(t *testing.T) {
	svc := &stubCryptoSvc{
		signFn: func(_ context.Context, _ keyServices.SignRequest) (*keyServices.SignResult, error) {
			return nil, errors.New("forbidden: cannot use other users' keys")
		},
	}

	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value": base64.StdEncoding.EncodeToString([]byte("data")),
	}))

	signKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestSignKey_DefaultAlgorithmRS256(t *testing.T) {
	svc := &stubCryptoSvc{
		signFn: func(_ context.Context, req keyServices.SignRequest) (*keyServices.SignResult, error) {
			assert.Equal(t, crypto.SignatureAlgorithm("RS256"), req.Algorithm)
			return &keyServices.SignResult{
				Signature: []byte("sig"),
				Algorithm: crypto.SignatureAlgorithm("RS256"),
			}, nil
		},
	}

	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	// Omit algorithm — should default to RS256.
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value": base64.StdEncoding.EncodeToString([]byte("data")),
	}))

	signKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- verifyKey tests ---

func TestVerifyKey_Success_Valid(t *testing.T) {
	svc := &stubCryptoSvc{
		verifyFn: func(_ context.Context, req keyServices.VerifyRequest) (*keyServices.VerifyResult, error) {
			return &keyServices.VerifyResult{
				Valid:      true,
				Algorithm:  crypto.SignatureAlgorithm("ES256"),
				KeyID:      req.KeyID,
			}, nil
		},
	}

	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value":     base64.StdEncoding.EncodeToString([]byte("data")),
		"signature": base64.StdEncoding.EncodeToString([]byte("sig")),
		"algorithm": "ES256",
	}))

	verifyKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	require.Equal(t, http.StatusOK, w.Code)
	var resp VerifyKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Valid)
	assert.Equal(t, "ES256", resp.Algorithm)
}

func TestVerifyKey_Success_Invalid(t *testing.T) {
	svc := &stubCryptoSvc{
		verifyFn: func(_ context.Context, _ keyServices.VerifyRequest) (*keyServices.VerifyResult, error) {
			return &keyServices.VerifyResult{Valid: false, Algorithm: "ES256"}, nil
		},
	}

	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value":     base64.StdEncoding.EncodeToString([]byte("data")),
		"signature": base64.StdEncoding.EncodeToString([]byte("bad-sig")),
		"algorithm": "ES256",
	}))

	verifyKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	require.Equal(t, http.StatusOK, w.Code)
	var resp VerifyKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Valid)
}

func TestVerifyKey_MissingFields_Returns400(t *testing.T) {
	c := newCryptoContext(nil)
	w := httptest.NewRecorder()
	// signature is absent.
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value": base64.StdEncoding.EncodeToString([]byte("data")),
	}))

	verifyKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyKey_InvalidSignatureBase64_Returns400(t *testing.T) {
	c := newCryptoContext(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value":     base64.StdEncoding.EncodeToString([]byte("data")),
		"signature": "not-valid!!!",
	}))

	verifyKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- encryptKey tests ---

func TestEncryptKey_Success(t *testing.T) {
	ciphertext := []byte("encrypted-bytes")
	svc := &stubCryptoSvc{
		encryptFn: func(_ context.Context, req keyServices.EncryptRequest) (*keyServices.EncryptResult, error) {
			assert.Equal(t, crypto.EncryptionAlgorithm("RSA-OAEP"), req.Algorithm)
			return &keyServices.EncryptResult{
				Ciphertext: ciphertext,
				Algorithm:  crypto.EncryptionAlgorithm("RSA-OAEP"),
			}, nil
		},
	}

	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value":     base64.StdEncoding.EncodeToString([]byte("secret")),
		"algorithm": "RSA-OAEP",
	}))

	encryptKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	require.Equal(t, http.StatusOK, w.Code)
	var resp EncryptKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, base64.StdEncoding.EncodeToString(ciphertext), resp.Value)
	assert.Equal(t, "RSA-OAEP", resp.Algorithm)
	assert.Empty(t, resp.Nonce)
}

func TestEncryptKey_AESGCMIncludesNonce(t *testing.T) {
	ciphertext := []byte("ct")
	nonce := []byte("nonce-bytes")
	svc := &stubCryptoSvc{
		encryptFn: func(_ context.Context, req keyServices.EncryptRequest) (*keyServices.EncryptResult, error) {
			return &keyServices.EncryptResult{
				Ciphertext: ciphertext,
				Nonce:      nonce,
				Algorithm:  crypto.EncryptionAlgorithm("AES256-GCM"),
			}, nil
		},
	}

	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value":     base64.StdEncoding.EncodeToString([]byte("plaintext")),
		"algorithm": "AES256-GCM",
	}))

	encryptKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	require.Equal(t, http.StatusOK, w.Code)
	var resp EncryptKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, base64.StdEncoding.EncodeToString(nonce), resp.Nonce)
}

func TestEncryptKey_DefaultAlgorithmRSAOAEP(t *testing.T) {
	svc := &stubCryptoSvc{
		encryptFn: func(_ context.Context, req keyServices.EncryptRequest) (*keyServices.EncryptResult, error) {
			assert.Equal(t, crypto.EncryptionAlgorithm("RSA-OAEP"), req.Algorithm)
			return &keyServices.EncryptResult{Ciphertext: []byte("ct"), Algorithm: "RSA-OAEP"}, nil
		},
	}

	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value": base64.StdEncoding.EncodeToString([]byte("data")),
	}))

	encryptKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestEncryptKey_MissingValue_Returns400(t *testing.T) {
	c := newCryptoContext(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{"algorithm": "RSA-OAEP"}))

	encryptKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEncryptKey_UnsupportedAlgorithm_Returns400(t *testing.T) {
	svc := &stubCryptoSvc{
		encryptFn: func(_ context.Context, _ keyServices.EncryptRequest) (*keyServices.EncryptResult, error) {
			return nil, errors.New("unsupported algorithm: FOOBAR")
		},
	}

	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value":     base64.StdEncoding.EncodeToString([]byte("data")),
		"algorithm": "FOOBAR",
	}))

	encryptKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- decryptKey tests ---

func TestDecryptKey_Success(t *testing.T) {
	plaintext := []byte("secret message")
	svc := &stubCryptoSvc{
		decryptFn: func(_ context.Context, req keyServices.DecryptRequest) (*keyServices.DecryptResult, error) {
			assert.Equal(t, crypto.EncryptionAlgorithm("RSA-OAEP"), req.Algorithm)
			assert.Nil(t, req.Nonce)
			return &keyServices.DecryptResult{
				Plaintext: plaintext,
				Algorithm: crypto.EncryptionAlgorithm("RSA-OAEP"),
			}, nil
		},
	}

	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value":     base64.StdEncoding.EncodeToString([]byte("ciphertext")),
		"algorithm": "RSA-OAEP",
	}))

	decryptKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	require.Equal(t, http.StatusOK, w.Code)
	var resp DecryptKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, base64.StdEncoding.EncodeToString(plaintext), resp.Value)
	assert.Equal(t, "RSA-OAEP", resp.Algorithm)
}

func TestDecryptKey_WithNonce(t *testing.T) {
	svc := &stubCryptoSvc{
		decryptFn: func(_ context.Context, req keyServices.DecryptRequest) (*keyServices.DecryptResult, error) {
			assert.Equal(t, []byte("nonce-val"), req.Nonce)
			return &keyServices.DecryptResult{Plaintext: []byte("pt"), Algorithm: "AES256-GCM"}, nil
		},
	}

	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value":     base64.StdEncoding.EncodeToString([]byte("ct")),
		"nonce":     base64.StdEncoding.EncodeToString([]byte("nonce-val")),
		"algorithm": "AES256-GCM",
	}))

	decryptKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDecryptKey_InvalidNonceBase64_Returns400(t *testing.T) {
	c := newCryptoContext(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value": base64.StdEncoding.EncodeToString([]byte("ct")),
		"nonce": "not-valid-base64!!!",
	}))

	decryptKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDecryptKey_MissingValue_Returns400(t *testing.T) {
	c := newCryptoContext(nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{"algorithm": "RSA-OAEP"}))

	decryptKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDecryptKey_KeyNotFound_Returns404(t *testing.T) {
	svc := &stubCryptoSvc{
		decryptFn: func(_ context.Context, _ keyServices.DecryptRequest) (*keyServices.DecryptResult, error) {
			return nil, errors.New("key not found: sql: no rows")
		},
	}

	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value":     base64.StdEncoding.EncodeToString([]byte("ct")),
		"algorithm": "RSA-OAEP",
	}))

	decryptKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDecryptKey_RevokedKey_Returns403(t *testing.T) {
	svc := &stubCryptoSvc{
		decryptFn: func(_ context.Context, _ keyServices.DecryptRequest) (*keyServices.DecryptResult, error) {
			return nil, errors.New("cannot decrypt with revoked key")
		},
	}

	c := newCryptoContext(svc)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value":     base64.StdEncoding.EncodeToString([]byte("ct")),
		"algorithm": "RSA-OAEP",
	}))

	decryptKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// --- uuid parsing guard (invalid key_id) ---

func TestSignKey_InvalidKeyID_Returns400(t *testing.T) {
	c := &Context{
		Params: &ApiParams{KeyID: "not-a-uuid"},
		Claims: jwt.MapClaims{"user_id": testUserIDStr},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value": base64.StdEncoding.EncodeToString([]byte("data")),
	}))

	signKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- nil container guard ---

func TestSignKey_NilContainer_Returns500(t *testing.T) {
	// App is present but ServiceContainer is nil.
	c := &Context{
		App:    &app.App{ServiceContainer: nil},
		Params: &ApiParams{KeyID: testKeyIDStr},
		Claims: jwt.MapClaims{"user_id": testUserIDStr},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{
		"value": base64.StdEncoding.EncodeToString([]byte("data")),
	}))

	signKey(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
