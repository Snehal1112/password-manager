package vaultaccess

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/internal/apitest"
	"rocketvault/model"
)

func TestListRemote_PrintsSameColumnsAsLocal(t *testing.T) {
	assignment := &model.RoleAssignment{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		Role:          "Key Vault Administrator",
	}

	roleSvc := &testutils.MockRoleAssignmentService{}
	roleSvc.On("ListAssignments", mock.Anything, mock.Anything).
		Return([]*model.RoleAssignment{assignment}, nil)
	roleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()

	srv := apitest.New(t, apitest.Options{RoleAssignments: roleSvc})

	cmd, out := remoteTestCmd(t, "payments")
	require.NoError(t, runListRemote(cmd, srv.Client(), srv.Target()))

	got := out.String()
	assert.Contains(t, got, "ASSIGNMENT-ID")
	assert.Contains(t, got, "ROLE")
	assert.Contains(t, got, "PRINCIPAL-ID")
	assert.Contains(t, got, assignment.ID.String())
	assert.Contains(t, got, "Key Vault Administrator")
}
