// Package api — internal tests for vault-scoped role-assignment handlers.
package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/app"
	authzServices "rocketvault/internal/services/authorization"
)

// newRoleAssignmentCtx builds a Context whose session carries the given role,
// backed by the given AccessPolicyService. It reuses policyContainer from
// access_policies_test.go. A nil RoleAssignmentService is fine for the gate
// path because the gate rejects before the role-assignment service is touched.
func newRoleAssignmentCtx(role string, policySvc authzServices.AccessPolicyService) *Context {
	a := &app.App{ServiceContainer: &policyContainer{policySvc: policySvc}}
	return &Context{
		App: a,
		Claims: jwt.MapClaims{
			"user_id": "00000000-0000-0000-0000-000000000001",
			"role":    role,
		},
		Params: &ApiParams{VaultName: "prod", PerPage: 60},
	}
}

// TestRoleAssignments_GrantRequiresAdmin verifies a non-admin caller without a
// vaults/manage policy is rejected with 403 before the service is invoked.
func TestRoleAssignments_GrantRequiresAdmin(t *testing.T) {
	// Non-admin: requireVaultManage falls through to CheckAccess, which returns
	// AccessFallback (no policy), so the caller is denied.
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	c := newRoleAssignmentCtx("user", policySvc)
	w := httptest.NewRecorder()
	body := []byte(`{"principal":"alice","role":"secrets-user"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/prod/role-assignments", bytes.NewReader(body))

	createRoleAssignment(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}
