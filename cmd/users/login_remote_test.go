package users

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/cliclient"
	"rocketvault/internal/vaultapi"
)

// remoteLoginCmd builds a login command carrying the context a remote
// pre-run would have stashed: the target and a vaultapi client pointed at
// srv, with no usable token source (login is what creates one).
func remoteLoginCmd(t *testing.T, srv *httptest.Server) (*cobra.Command, *cliclient.Target) {
	t.Helper()

	client, err := vaultapi.New(vaultapi.Config{
		BaseURL: srv.URL, HTTPClient: srv.Client(),
		Tokens: staticRemoteToken(""), DisableRetry: true,
	})
	require.NoError(t, err)

	target := &cliclient.Target{Server: srv.URL}
	ctx := context.WithValue(context.Background(), common.RemoteTargetKey, target)
	ctx = context.WithValue(ctx, common.RemoteClientKey, client)

	// runRemoteLogin reads its credentials from the command's own flag set,
	// so the flags must exist here the same way InitUsersLogin registers them.
	c := &cobra.Command{Use: "login"}
	c.Flags().String("username", "", "")
	c.Flags().String("password", "", "")
	c.Flags().String("totp-code", "", "")
	c.Flags().Bool("oidc", false, "")
	c.SetContext(ctx)
	return c, target
}

type staticRemoteToken string

func (s staticRemoteToken) Token(context.Context) (string, error) { return string(s), nil }

func loginResponder(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/users/login", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": "remote-tok", "refresh_token": "remote-refresh",
			"user_id":  "0f2b6f1e-0000-0000-0000-000000000001",
			"username": "admin", "roles": []string{"admin"},
		})
	}))
}

// A remote login must land in the server-scoped session file and leave any
// local session for the same username untouched.
func TestRunRemoteLogin_WritesServerScopedSession(t *testing.T) {
	common.SessionBaseDir = t.TempDir()

	// A pre-existing local session for the same user must survive.
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Username: "admin", Token: "local-tok", ServerKey: common.LocalServerKey,
		ExpiresAt: time.Now().Add(time.Hour),
	}))

	srv := loginResponder(t)
	defer srv.Close()

	c, target := remoteLoginCmd(t, srv)
	require.NoError(t, c.Flags().Set("username", "admin"))
	require.NoError(t, c.Flags().Set("password", "pw"))
	require.NoError(t, c.Flags().Set("totp-code", "123456"))
	require.NoError(t, runRemoteLogin(c, target))

	serverKey := common.SanitizeServerKey(srv.URL)
	remote, err := common.LoadSessionForServer(serverKey, "admin")
	require.NoError(t, err)
	require.NotNil(t, remote, "a remote login must write a server-scoped session")
	assert.Equal(t, "remote-tok", remote.Token)

	local, err := common.LoadSessionForServer(common.LocalServerKey, "admin")
	require.NoError(t, err)
	require.NotNil(t, local, "the local session must survive a remote login")
	assert.Equal(t, "local-tok", local.Token)

	current, err := common.LoadCurrentSession()
	require.NoError(t, err)
	require.NotNil(t, current)
	assert.Equal(t, serverKey, current.ServerKey, "current must point at the remote session")
}

// A remote logout deletes the server-scoped file and leaves the local one.
func TestRunLogout_RemoteServerKey_LeavesLocalSession(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	serverKey := common.SanitizeServerKey("https://vault.example.com")

	require.NoError(t, common.SaveSession(&common.SessionCache{
		Username: "admin", Token: "local-tok", ServerKey: common.LocalServerKey,
		ExpiresAt: time.Now().Add(time.Hour),
	}))
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Username: "admin", Token: "remote-tok", ServerKey: serverKey,
		ExpiresAt: time.Now().Add(time.Hour),
	}))

	require.NoError(t, runLogout(serverKey, "admin"))

	remote, err := common.LoadSessionForServer(serverKey, "admin")
	require.NoError(t, err)
	assert.Nil(t, remote, "the remote session must be deleted")

	local, err := common.LoadSessionForServer(common.LocalServerKey, "admin")
	require.NoError(t, err)
	require.NotNil(t, local, "the local session must be left alone")
	assert.Equal(t, "local-tok", local.Token)
}

// The mirror: a local logout must not delete a remote session.
func TestRunLogout_LocalServerKey_LeavesRemoteSession(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	serverKey := common.SanitizeServerKey("https://vault.example.com")

	require.NoError(t, common.SaveSession(&common.SessionCache{
		Username: "admin", Token: "remote-tok", ServerKey: serverKey,
		ExpiresAt: time.Now().Add(time.Hour),
	}))
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Username: "admin", Token: "local-tok", ServerKey: common.LocalServerKey,
		ExpiresAt: time.Now().Add(time.Hour),
	}))

	require.NoError(t, runLogout(common.LocalServerKey, "admin"))

	local, err := common.LoadSessionForServer(common.LocalServerKey, "admin")
	require.NoError(t, err)
	assert.Nil(t, local)

	remote, err := common.LoadSessionForServer(serverKey, "admin")
	require.NoError(t, err)
	require.NotNil(t, remote, "the remote session must be left alone")
}

// With no username, a remote logout must not follow a current-session
// pointer that names a *local* session -- that would delete the wrong file.
func TestRunLogout_NoUsername_WrongServerCurrent_DeletesNothing(t *testing.T) {
	common.SessionBaseDir = t.TempDir()
	require.NoError(t, common.SaveSession(&common.SessionCache{
		Username: "admin", Token: "local-tok", ServerKey: common.LocalServerKey,
		ExpiresAt: time.Now().Add(time.Hour),
	}))

	remoteKey := common.SanitizeServerKey("https://vault.example.com")
	require.NoError(t, runLogout(remoteKey, ""))

	local, err := common.LoadSessionForServer(common.LocalServerKey, "admin")
	require.NoError(t, err)
	require.NotNil(t, local, "a remote logout must not delete the local session it did not target")
}
