package vaultaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cliclient"
	"rocketvault/internal/vaultapi"
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
	var gotPath, gotAuth string
	var gotBody vaultapi.GrantRoleRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":                 uuid.New().String(),
			"principal_id":       uuid.New().String(),
			"principal_username": "alice",
			"principal_type":     "user",
			"role":               "Key Vault Administrator",
			"vault_name":         "payments",
			"created_at":         "2026-09-03T10:00:00Z",
		})
	}))
	defer srv.Close()

	cmd, out := remoteTestCmd(t, "payments")

	err := runGrantRemote(cmd, remoteTestClient(t, srv), &cliclient.Target{Server: srv.URL},
		"alice", "Key Vault Administrator", "user")
	require.NoError(t, err)

	assert.Equal(t, "/api/v1/vaults/payments/role-assignments", gotPath)
	assert.Equal(t, "Bearer tok", gotAuth)
	assert.Equal(t, "alice", gotBody.Principal)
	assert.Equal(t, "Key Vault Administrator", gotBody.Role)
	assert.Equal(t, "user", gotBody.PrincipalType)
	assert.Contains(t, out.String(), "granted Key Vault Administrator to alice")
}

func TestGrantRemote_ForbiddenIsReadable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	cmd, _ := remoteTestCmd(t, "payments")

	err := runGrantRemote(cmd, remoteTestClient(t, srv), &cliclient.Target{Server: srv.URL},
		"alice", "Key Vault Administrator", "user")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role assignment")
}
