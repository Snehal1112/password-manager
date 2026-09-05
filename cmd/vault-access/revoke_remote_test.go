package vaultaccess

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/internal/apitest"
)

func TestRevokeRemote_DeletesByAssignmentID(t *testing.T) {
	id := uuid.New()

	roleSvc := &testutils.MockRoleAssignmentService{}
	roleSvc.On("RevokeAssignment", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil)
	roleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()

	srv := apitest.New(t, apitest.Options{RoleAssignments: roleSvc})

	cmd, out := remoteTestCmd(t, "payments")
	require.NoError(t, runRevokeRemote(cmd, srv.Client(), srv.Target(), id.String()))
	assert.Contains(t, out.String(), "revoked assignment "+id.String())
}

func TestRevokeRemote_RejectsPrincipalName(t *testing.T) {
	// No RevokeAssignment expectation: if a request reaches the handler, the
	// mock panics on the unregistered call rather than passing silently.
	roleSvc := &testutils.MockRoleAssignmentService{}
	roleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()

	srv := apitest.New(t, apitest.Options{RoleAssignments: roleSvc})

	cmd, _ := remoteTestCmd(t, "payments")

	err := runRevokeRemote(cmd, srv.Client(), srv.Target(), "alice")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "assignment id")
}
