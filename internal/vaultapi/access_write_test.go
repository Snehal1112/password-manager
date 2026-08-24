package vaultapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateRoleAssignment_PostsToTheVaultScopedRoute(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated,
		`{"id":"`+assignmentID+`","principal_id":"`+dbSecretID+`","principal_username":"mcp-agent",
		  "principal_type":"service_account","role":"Key Vault Secrets User","vault_name":"prod"}`)

	c := newClientForTest(t, srv)
	got, err := c.CreateRoleAssignment(context.Background(), "prod", GrantRoleRequest{
		Principal: "mcp-agent", PrincipalType: "service_account", Role: "Key Vault Secrets User",
	})
	require.NoError(t, err)

	require.Equal(t, http.MethodPost, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/role-assignments", probe.path)
	require.Equal(t, "Key Vault Secrets User", got.Role)
	require.Equal(t, "mcp-agent", got.PrincipalUsername)
}

func TestCreateRoleAssignment_SendsThePrincipalVerbatim(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{"id":"`+assignmentID+`"}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateRoleAssignment(context.Background(), "prod", GrantRoleRequest{
		Principal: "alice", Role: "Key Vault Reader",
	})
	require.NoError(t, err)

	require.Equal(t, "alice", probe.body["principal"],
		"the server resolves a username or UUID; the client must not")
	require.Equal(t, "Key Vault Reader", probe.body["role"])
}

func TestCreateRoleAssignment_AcceptsAUUIDPrincipal(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{"id":"`+assignmentID+`"}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateRoleAssignment(context.Background(), "prod", GrantRoleRequest{
		Principal: dbSecretID, Role: "Key Vault Reader",
	})
	require.NoError(t, err)
	require.Equal(t, dbSecretID, probe.body["principal"])
}

func TestCreateRoleAssignment_OmitsPrincipalTypeWhenUnset(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{"id":"`+assignmentID+`"}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateRoleAssignment(context.Background(), "prod", GrantRoleRequest{
		Principal: "alice", Role: "Key Vault Reader",
	})
	require.NoError(t, err)

	_, present := probe.body["principal_type"]
	require.False(t, present, "the server defaults it to user")
}

func TestCreateRoleAssignment_DoesNotValidateTheRoleName(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusBadRequest, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateRoleAssignment(context.Background(), "prod", GrantRoleRequest{
		Principal: "alice", Role: "Not A Real Role",
	})
	require.Error(t, err)
	require.Equal(t, 1, probe.calls,
		"the server owns the role list; a client-side copy would drift")
}

func TestCreateRoleAssignment_RequiresVaultPrincipalAndRole(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{}`)
	c := newClientForTest(t, srv)

	_, err := c.CreateRoleAssignment(context.Background(), "", GrantRoleRequest{Principal: "a", Role: "r"})
	require.ErrorContains(t, err, "vault is required")

	_, err = c.CreateRoleAssignment(context.Background(), "prod", GrantRoleRequest{Role: "r"})
	require.ErrorContains(t, err, "principal is required")

	_, err = c.CreateRoleAssignment(context.Background(), "prod", GrantRoleRequest{Principal: "a"})
	require.ErrorContains(t, err, "role is required")

	require.Zero(t, probe.calls)
}

func TestCreateRoleAssignment_ForbiddenNamesTheDataAccessAdminRole(t *testing.T) {
	srv, _ := vaultWriteServer(t, http.StatusForbidden, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateRoleAssignment(context.Background(), "prod", GrantRoleRequest{
		Principal: "alice", Role: "Key Vault Reader",
	})

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Contains(t, apiErr.Hint, "Key Vault Data Access Administrator")
}
