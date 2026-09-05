package apitest

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
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
