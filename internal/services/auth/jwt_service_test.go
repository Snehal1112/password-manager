package auth_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestJWTService_GenerateToken_EmbedsMultipleRoles is the regression test for
// widening GenerateToken's role parameter from a single role string to a role
// list, and JWTClaims.Role (string) to JWTClaims.Roles ([]string). It reuses
// the newProviderJWT/newStaticProvider test helpers already defined in
// jwt_service_provider_test.go rather than inventing a new signing provider.
func TestJWTService_GenerateToken_EmbedsMultipleRoles(t *testing.T) {
	svc := newProviderJWT(t)

	userID := uuid.New()
	sessionID := uuid.New()
	tokenStr, err := svc.GenerateToken(userID, "alice", []string{"admin", "secrets_manager"}, sessionID)
	require.NoError(t, err)

	claims, err := svc.ValidateToken(tokenStr)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"admin", "secrets_manager"}, claims.Roles)
}
