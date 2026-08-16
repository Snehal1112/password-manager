package audit

import (
	"context"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"rocketvault/common"
	"rocketvault/model"
)

// TestRequireAuditAdmin_MissingClaims proves a context with no ClaimsKey at
// all is rejected with the "unauthorized" message, not the "forbidden" one.
func TestRequireAuditAdmin_MissingClaims(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	claims, err := requireAuditAdmin(cmd)
	assert.Nil(t, claims)
	assert.ErrorContains(t, err, "unauthorized: missing authentication claims")
}

// TestRequireAuditAdmin_NonAdminRole proves an authenticated non-admin caller
// is rejected with the "forbidden" message.
func TestRequireAuditAdmin_NonAdminRole(t *testing.T) {
	cmd := &cobra.Command{}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, &model.Claims{Role: model.RoleUser})
	cmd.SetContext(ctx)

	claims, err := requireAuditAdmin(cmd)
	assert.Nil(t, claims)
	assert.ErrorContains(t, err, "forbidden: requires admin role")
}

// TestRequireAuditAdmin_AdminRole proves an admin caller passes and gets
// their claims back.
func TestRequireAuditAdmin_AdminRole(t *testing.T) {
	cmd := &cobra.Command{}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, &model.Claims{Role: model.RoleAdmin, Username: "admin"})
	cmd.SetContext(ctx)

	claims, err := requireAuditAdmin(cmd)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, model.RoleAdmin, claims.Role)
}
