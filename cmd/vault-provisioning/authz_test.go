package vaultprovisioning

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/model"
)

func ctxWithClaims(userID uuid.UUID, roles []string) context.Context {
	return context.WithValue(context.Background(), common.ClaimsKey,
		&model.Claims{UserID: userID, Roles: roles})
}

func TestRequireGrantAdmin_AllowsAdmin(t *testing.T) {
	id := uuid.New()

	got, err := requireGrantAdmin(ctxWithClaims(id, []string{string(model.RoleAdmin)}))

	require.NoError(t, err)
	require.Equal(t, id, got, "the acting principal must be returned so the audit entry names somebody")
}

func TestRequireGrantAdmin_DeniesNonAdmin(t *testing.T) {
	_, err := requireGrantAdmin(ctxWithClaims(uuid.New(), []string{"user"}))

	require.Error(t, err)
	require.Contains(t, err.Error(), "admin")
}

func TestRequireGrantAdmin_DeniesVaultManageHolder(t *testing.T) {
	// A principal with vault-management rights is still not a grant admin:
	// this tier is deliberately non-delegable.
	_, err := requireGrantAdmin(ctxWithClaims(uuid.New(), []string{"vault-admin"}))

	require.Error(t, err)
}

func TestRequireGrantAdmin_MissingClaimsIsAnError(t *testing.T) {
	_, err := requireGrantAdmin(context.Background())

	require.Error(t, err, "reaching this helper unauthenticated is a wiring bug, not a permission denial")
}
