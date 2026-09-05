package apitest

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	authServices "rocketvault/internal/services/auth"
	"rocketvault/model"
)

// TestNew_ServesTheRealHandler proves the response body is marshalled by the
// production handler, not by this test. listRoleAssignments enriches each row
// with VaultName and ExpandedPolicyCount -- fields the service layer never
// returns -- so their presence is only explicable by the real handler running.
func TestNew_ServesTheRealHandler(t *testing.T) {
	assignment := &model.RoleAssignment{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		Role:          "Key Vault Secrets User",
	}

	roleSvc := &testutils.MockRoleAssignmentService{}
	roleSvc.On("ListAssignments", mock.Anything, mock.Anything).
		Return([]*model.RoleAssignment{assignment}, nil)
	roleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()

	srv := New(t, Options{RoleAssignments: roleSvc})

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL()+"/api/v1/vaults/payments/role-assignments", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var decoded model.ListRoleAssignmentsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&decoded))
	require.Len(t, decoded.RoleAssignments, 1)
	assert.Equal(t, assignment.ID.String(), decoded.RoleAssignments[0].ID)
	assert.Equal(t, "payments", decoded.RoleAssignments[0].VaultName,
		"VaultName is set by the handler, not the service -- if this is empty the real handler did not run")
}

// TestServer_ClientSendsBearerToken proves the harness client's token reaches
// AuthenticationMiddleware -- the auth-header plumbing is covered, not assumed.
// It also proves the shape guard the package comment promises: the assertion
// on RoleAssignment.VaultName below decodes through vaultapi's own
// independently-declared roleAssignmentWire (internal/vaultapi/access.go),
// not through the model type the handler marshals from, so a tag rename on
// the model side leaves the wire struct stale and the decode empty -- see
// the CONTROLLER AMENDMENT proof recorded in task-2-report.md.
func TestServer_ClientSendsBearerToken(t *testing.T) {
	var gotToken string

	assignment := &model.RoleAssignment{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		Role:          "Key Vault Secrets User",
	}

	roleSvc := &testutils.MockRoleAssignmentService{}
	roleSvc.On("ListAssignments", mock.Anything, mock.Anything).
		Return([]*model.RoleAssignment{assignment}, nil)
	roleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()

	srv := New(t, Options{RoleAssignments: roleSvc})

	// Re-register ValidateSession to capture what the middleware received.
	srv.tc.MockAuthService.ExpectedCalls = nil
	srv.tc.MockAuthService.On("ValidateSession", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { gotToken = args.String(1) }).
		Return(&authServices.JWTClaims{
			UserID: srv.tc.TestUserID, Username: "testuser", Roles: []string{model.RoleAdmin},
		}, nil)

	assignments, _, err := srv.Client().ListRoleAssignments(context.Background(), "payments", 0)
	require.NoError(t, err)
	assert.Equal(t, testToken, gotToken, "the client's bearer token must reach the auth middleware")
	require.Len(t, assignments, 1)
	assert.Equal(t, "payments", assignments[0].VaultName,
		"decoded via vaultapi's own wire struct -- a stale tag here yields an empty VaultName")

	assert.Equal(t, srv.URL(), srv.Target().Server)
}
