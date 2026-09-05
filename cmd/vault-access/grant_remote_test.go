package vaultaccess

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/internal/apitest"
	"rocketvault/internal/vaultapi"
	"rocketvault/model"
)

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

// remoteTestCmd builds a command whose --vault flag is *Set* rather than
// defaulted. ResolveRemoteVault only reads the flag when Flags().Changed is
// true, so a defaulted-but-unset flag would fall through to "default" and
// every path assertion in this file would miss.
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

func remoteTestClient(t *testing.T, srv *httptest.Server) *vaultapi.Client {
	t.Helper()
	client, err := vaultapi.New(vaultapi.Config{
		BaseURL: srv.URL, HTTPClient: srv.Client(),
		Tokens: staticToken("tok"), DisableRetry: true,
	})
	require.NoError(t, err)
	return client
}

func TestGrantRemote_PostsToTheVaultScopedRoute(t *testing.T) {
	created := &model.RoleAssignment{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		Role:          "Key Vault Administrator",
	}

	roleSvc := &testutils.MockRoleAssignmentService{}
	roleSvc.On("AssignRole", mock.Anything, mock.Anything).Return(created, nil)
	roleSvc.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(true, nil).Maybe()

	srv := apitest.New(t, apitest.Options{RoleAssignments: roleSvc})

	cmd, out := remoteTestCmd(t, "payments")

	err := runGrantRemote(cmd, srv.Client(), srv.Target(),
		"alice", "Key Vault Administrator", "user")
	require.NoError(t, err)

	assert.Contains(t, out.String(), "granted Key Vault Administrator to alice")
	assert.Contains(t, out.String(), created.ID.String(),
		"the assignment id must come back through the real response shape")
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
