package vaultaccess

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/internal/apitest"
	authz "rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// remoteTestCmd builds a command whose --vault flag is *Set* rather than
// defaulted. ResolveRemoteVault only reads the flag when Flags().Changed is
// true, so a defaulted-but-unset flag would fall through to "default" and the
// --vault assertions below (gotVault, TestGrantRemote_PostsToTheVaultScopedRoute)
// would miss: the flag would resolve to "default" regardless of what the test
// passed in.
func remoteTestCmd(t *testing.T, vault string) (*cobra.Command, *bytes.Buffer) {
	t.Helper()
	// ResolveRemoteVault consults this, so neutralise the developer's shell.
	t.Setenv("ROCKETVAULT_VAULT", "")

	c := &cobra.Command{}
	c.Flags().String("vault", "", "")
	require.NoError(t, c.Flags().Set("vault", vault))
	out := &bytes.Buffer{}
	c.SetOut(out)
	c.SetContext(context.Background())
	return c, out
}

func TestGrantRemote_PostsToTheVaultScopedRoute(t *testing.T) {
	created := &model.RoleAssignment{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		Role:          "Key Vault Administrator",
	}

	var gotInput authz.AssignRoleInput
	roleSvc := &testutils.MockRoleAssignmentService{}
	roleSvc.On("AssignRole", mock.Anything, mock.Anything).
		Run(func(a mock.Arguments) { gotInput = a.Get(1).(authz.AssignRoleInput) }).
		Return(created, nil)
	roleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()

	srv := apitest.New(t, apitest.Options{RoleAssignments: roleSvc})

	var gotVault string
	vs := srv.TestContext().MockVaultService
	vs.ExpectedCalls = nil
	vs.On("GetVault", mock.Anything, mock.Anything).
		Run(func(a mock.Arguments) { gotVault = a.String(1) }).
		Return(&model.Vault{ID: srv.TestContext().TestVaultID, Name: "payments", Enabled: true}, nil).Maybe()

	cmd, out := remoteTestCmd(t, "payments")

	err := runGrantRemote(cmd, srv.Client(), srv.Target(),
		"alice", "Key Vault Administrator", "user")
	require.NoError(t, err)

	assert.Contains(t, out.String(), "granted Key Vault Administrator to alice")
	assert.Contains(t, out.String(), created.ID.String(),
		"the assignment id must come back through the real response shape")
	assert.Equal(t, "payments", gotVault, "--vault must reach the URL")
	assert.Equal(t, "alice", gotInput.Principal)
	assert.Equal(t, "Key Vault Administrator", gotInput.Role)
	assert.Equal(t, model.PrincipalTypeUser, gotInput.PrincipalType)
}

func TestGrantRemote_ForbiddenIsReadable(t *testing.T) {
	roleSvc := &testutils.MockRoleAssignmentService{}

	srv := apitest.New(t, apitest.Options{
		RoleAssignments:  roleSvc,
		DenyAccessPolicy: true,
	})

	cmd, _ := remoteTestCmd(t, "payments")

	err := runGrantRemote(cmd, srv.Client(), srv.Target(),
		"alice", "Key Vault Administrator", "user")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role assignment")
}
