// Package api — internal tests for vault-scoped role-assignment handlers.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/app"
	"rocketvault/common"
	authzServices "rocketvault/internal/services/authorization"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// mockRoleAssignmentService is a local testify mock for authzServices.RoleAssignmentService.
type mockRoleAssignmentService struct {
	mock.Mock
}

func (m *mockRoleAssignmentService) AssignRole(ctx context.Context, in authzServices.AssignRoleInput) (*model.RoleAssignment, error) {
	args := m.Called(ctx, in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RoleAssignment), args.Error(1)
}

func (m *mockRoleAssignmentService) RevokeAssignment(ctx context.Context, assignmentID, vaultID uuid.UUID) error {
	args := m.Called(ctx, assignmentID, vaultID)
	return args.Error(0)
}

func (m *mockRoleAssignmentService) ListAssignments(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	args := m.Called(ctx, vaultID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.RoleAssignment), args.Error(1)
}

func (m *mockRoleAssignmentService) HasDataAction(ctx context.Context, principalID, vaultID uuid.UUID, action model.DataAction) (bool, error) {
	args := m.Called(ctx, principalID, vaultID, action)
	return args.Bool(0), args.Error(1)
}

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

// TestListRoleAssignments_ReturnsEnrichedResponse verifies the list handler
// returns the ListRoleAssignmentsResponse shape (not a raw model array/map),
// with vault_name filled from the URL and expanded_policy_count derived from
// the role bundle.
func TestListRoleAssignments_ReturnsEnrichedResponse(t *testing.T) {
	vaultID := uuid.New()
	principalID := uuid.New()
	assignment := &model.RoleAssignment{
		ID:            uuid.New(),
		PrincipalID:   principalID,
		PrincipalType: model.PrincipalTypeUser,
		Role:          "secrets-user", // bundle = get, list => 2 policies
		VaultID:       vaultID,
	}

	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("ListAssignments", mock.Anything, mock.Anything).Return([]*model.RoleAssignment{assignment}, nil)

	mc := &testutils.MockServiceContainer{}
	mc.On("GetRoleAssignmentService").Return(roleSvc)

	c := &Context{
		App:    &app.App{ServiceContainer: mc},
		Claims: jwt.MapClaims{"user_id": "00000000-0000-0000-0000-000000000001", "role": "user"},
		Params: &ApiParams{VaultName: "prod", PerPage: 60},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/vaults/prod/role-assignments", nil)

	listRoleAssignments(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusOK, w.Code)

	var resp model.ListRoleAssignmentsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	assert.Equal(t, 1, resp.Total)
	assert.Len(t, resp.RoleAssignments, 1)
	assert.Equal(t, "prod", resp.RoleAssignments[0].VaultName)
	assert.Equal(t, 2, resp.RoleAssignments[0].ExpandedPolicyCount)
	assert.Equal(t, assignment.ID.String(), resp.RoleAssignments[0].ID)
}

// TestRoleAssignments_GrantAllowedForDataAccessAdministrator proves a
// non-admin holding Key Vault Data Access Administrator in the target vault
// can create a role assignment there — the fix for the documented known
// limitation (role-assignment management was global-admin-only).
func TestRoleAssignments_GrantAllowedForDataAccessAdministrator(t *testing.T) {
	vaultID := uuid.New()
	callerID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, callerID, vaultID, model.ActionRoleAssignmentsWrite).
		Return(true, nil)
	roleSvc.On("AssignRole", mock.Anything, mock.Anything).
		Return(&model.RoleAssignment{ID: uuid.New(), VaultID: vaultID, Role: "Key Vault Secrets User"}, nil)

	mc := &testutils.MockServiceContainer{}
	mc.On("GetAccessPolicyService").Return(policySvc)
	mc.On("GetRoleAssignmentService").Return(roleSvc)

	c := &Context{
		App:    &app.App{ServiceContainer: mc},
		Claims: jwt.MapClaims{"user_id": callerID.String(), "role": "user"},
		Params: &ApiParams{VaultName: "prod", PerPage: 60},
	}
	body := []byte(`{"principal":"alice","role":"Key Vault Secrets User"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/prod/role-assignments", bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, vaultID.String()))
	w := httptest.NewRecorder()

	createRoleAssignment(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusCreated, w.Code)
}

// TestRoleAssignments_GrantDeniedForDataAccessAdministratorInWrongVault
// proves the grant is scoped: holding Key Vault Data Access Administrator in
// vault A does not authorize creating a role assignment in vault B.
func TestRoleAssignments_GrantDeniedForDataAccessAdministratorInWrongVault(t *testing.T) {
	grantedVault := uuid.New()
	targetVault := uuid.New()
	callerID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	roleSvc := &mockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, callerID, targetVault, model.ActionRoleAssignmentsWrite).
		Return(false, nil)
	_ = grantedVault // the grant (not registered on roleSvc at all) is scoped elsewhere; omitted here since HasDataAction is queried only against targetVault

	mc := &testutils.MockServiceContainer{}
	mc.On("GetAccessPolicyService").Return(policySvc)
	mc.On("GetRoleAssignmentService").Return(roleSvc)

	c := &Context{
		App:    &app.App{ServiceContainer: mc},
		Claims: jwt.MapClaims{"user_id": callerID.String(), "role": "user"},
		Params: &ApiParams{VaultName: "other", PerPage: 60},
	}
	body := []byte(`{"principal":"alice","role":"Key Vault Secrets User"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/vaults/other/role-assignments", bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, targetVault.String()))
	w := httptest.NewRecorder()

	createRoleAssignment(c, w, r)
	if c.Err != nil {
		writeError(w, c)
	}

	assert.Equal(t, http.StatusForbidden, w.Code)
}
