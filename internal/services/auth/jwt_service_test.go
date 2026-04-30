package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTService_ValidateToken_ExpiredTokenRejected(t *testing.T) {
	svc := NewJWTService(JWTConfig{
		SecretKey: "test-secret-key-that-is-long-enough",
		Issuer:    "rocketvault",
		Audience:  "PASSWORD_MANAGER",
		Expiry:    -1 * time.Second, // already expired at generation time
	})

	userID := uuid.New()
	token, err := svc.GenerateToken(userID, "alice", "user")
	require.NoError(t, err)

	time.Sleep(2 * time.Millisecond) // ensure we're past expiry

	_, err = svc.ValidateToken(token)
	assert.Error(t, err, "expired token must be rejected")
	assert.Contains(t, err.Error(), "invalid JWT token")
}

func TestJWTService_ValidateToken_ValidTokenAccepted(t *testing.T) {
	svc := NewJWTService(JWTConfig{
		SecretKey: "test-secret-key-that-is-long-enough",
		Issuer:    "rocketvault",
		Audience:  "PASSWORD_MANAGER",
		Expiry:    time.Hour,
	})

	userID := uuid.New()
	token, err := svc.GenerateToken(userID, "bob", "admin")
	require.NoError(t, err)

	claims, err := svc.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, "bob", claims.Username)
}
