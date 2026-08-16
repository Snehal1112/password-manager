package auth_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/auth"
	"rocketvault/internal/signing"
)

// staticProvider is a minimal SigningKeyProvider for testing.
type staticProvider struct {
	key *ecdsa.PrivateKey
	kid string
}

func newStaticProvider(t *testing.T) *staticProvider {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &staticProvider{key: key, kid: "test-kid-abc123"}
}

func (p *staticProvider) PrivateKey() crypto.Signer { return p.key }
func (p *staticProvider) Algorithm() string         { return "ES256" }
func (p *staticProvider) KeyID() string             { return p.kid }
func (p *staticProvider) PublicKeys() []signing.PublicKeyInfo {
	return []signing.PublicKeyInfo{{
		KeyID:     p.kid,
		Algorithm: "ES256",
		PublicKey: p.key.Public(),
	}}
}

func newProviderJWT(t *testing.T, extraCfg ...func(*auth.JWTConfig)) auth.JWTService {
	t.Helper()
	provider := newStaticProvider(t)
	cfg := auth.JWTConfig{
		Issuer:   "rocketvault",
		Audience: "PASSWORD_MANAGER",
		Expiry:   time.Hour,
	}
	for _, fn := range extraCfg {
		fn(&cfg)
	}
	return auth.NewJWTServiceWithProvider(cfg, provider)
}

func TestJWTService_Provider_GenerateAndValidate_ES256(t *testing.T) {
	svc := newProviderJWT(t)

	userID := uuid.New()
	sessionID := uuid.New()
	token, err := svc.GenerateToken(userID, "alice", "admin", sessionID)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	claims, err := svc.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, "alice", claims.Username)
	assert.Equal(t, "admin", claims.Role)
	assert.Equal(t, sessionID.String(), claims.ID, "jti must match the session ID")
}

func TestJWTService_Provider_ExpiredToken_Rejected(t *testing.T) {
	svc := newProviderJWT(t, func(c *auth.JWTConfig) {
		c.Expiry = -time.Second
	})

	userID := uuid.New()
	token, err := svc.GenerateToken(userID, "bob", "user", uuid.New())
	require.NoError(t, err)

	time.Sleep(2 * time.Millisecond)

	_, err = svc.ValidateToken(token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JWT token")
}

func TestJWTService_Provider_HS256Fallback_ActiveWindow(t *testing.T) {
	// Generate an HS256 token using the legacy service.
	legacySvc := auth.NewJWTService(auth.JWTConfig{
		SecretKey: "legacy-secret-key-1234567890",
		Issuer:    "rocketvault",
		Audience:  "PASSWORD_MANAGER",
		Expiry:    time.Hour,
	})
	userID := uuid.New()
	hs256Token, err := legacySvc.GenerateToken(userID, "carol", "user", uuid.New())
	require.NoError(t, err)

	// Provider service with a 1-hour migration window should accept the HS256 token.
	svc := newProviderJWT(t, func(c *auth.JWTConfig) {
		c.SecretKey = "legacy-secret-key-1234567890"
		c.MigrationWindow = time.Hour
	})

	claims, err := svc.ValidateToken(hs256Token)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
}

func TestJWTService_Provider_HS256Fallback_ExpiredWindow_Rejected(t *testing.T) {
	legacySvc := auth.NewJWTService(auth.JWTConfig{
		SecretKey: "legacy-secret-key-1234567890",
		Issuer:    "rocketvault",
		Audience:  "PASSWORD_MANAGER",
		Expiry:    time.Hour,
	})
	userID := uuid.New()
	hs256Token, err := legacySvc.GenerateToken(userID, "dave", "user", uuid.New())
	require.NoError(t, err)

	// Migration window of -1ns is already expired at construction.
	svc := newProviderJWT(t, func(c *auth.JWTConfig) {
		c.SecretKey = "legacy-secret-key-1234567890"
		c.MigrationWindow = -time.Nanosecond
	})

	_, err = svc.ValidateToken(hs256Token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "migration window expired")
}

func TestJWTService_Provider_UnknownKid_Rejected(t *testing.T) {
	// A token signed with a different key (unknown kid) must be rejected.
	otherProvider := newStaticProvider(t)
	otherProvider.kid = "unknown-kid"
	otherSvc := auth.NewJWTServiceWithProvider(auth.JWTConfig{
		Issuer:   "rocketvault",
		Audience: "PASSWORD_MANAGER",
		Expiry:   time.Hour,
	}, otherProvider)

	userID := uuid.New()
	token, err := otherSvc.GenerateToken(userID, "eve", "user", uuid.New())
	require.NoError(t, err)

	// Our service has a different kid — unknown-kid won't be in its PublicKeys().
	svc := newProviderJWT(t)
	_, err = svc.ValidateToken(token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown kid")
}

// leakedJWTSecret is the exact HS256 secret that was committed to
// .rocketvault.yaml and is therefore public in git history. The forgery test
// below signs with it deliberately: the point is that even a *correct* HMAC
// signature over well-formed claims must not authenticate anybody.
const leakedJWTSecret = "***SECRET-REMOVED-2026-08-17***"

// forgedHS256Token mints a token the way the 2026-08-16 pentest did: no kid
// header, HS256 signature, correct issuer/audience, and a jti that a normal
// low-privilege login would have produced. It is built with golang-jwt
// directly, not through any RocketVault constructor, so it keeps modelling the
// attacker's capability after every symmetric code path is gone.
func forgedHS256Token(t *testing.T, secret string) string {
	t.Helper()
	now := time.Now()
	claims := auth.JWTClaims{
		UserID:   uuid.New(),
		Username: "vaultuser1",
		Role:     "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "rocketvault",
			Subject:   uuid.New().String(),
			Audience:  jwt.ClaimStrings{"PASSWORD_MANAGER"},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	require.NoError(t, err)
	return signed
}

// TestJWTService_Provider_KidlessHS256Token_Rejected is the regression test for
// pentest finding H1. The service is configured the way production was — with
// the leaked secret and an open migration window — and must still reject the
// forged token, because the HS256 verification path no longer exists.
func TestJWTService_Provider_KidlessHS256Token_Rejected(t *testing.T) {
	svc := newProviderJWT(t, func(c *auth.JWTConfig) {
		c.SecretKey = leakedJWTSecret
		c.MigrationWindow = time.Hour
	})

	claims, err := svc.ValidateToken(forgedHS256Token(t, leakedJWTSecret))

	require.Error(t, err, "a token with no kid header must never be accepted")
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "missing kid header")
}
