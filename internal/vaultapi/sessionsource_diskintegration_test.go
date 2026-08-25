package vaultapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
)

// TestSessionSource_RecoversFromARealCLILoginOnDisk reproduces the exact
// 2026-08-24 failure end to end: a SessionSource constructed before a newer
// `rocketvault users login` writes to the real on-disk session cache must
// recover on its very next Token call, with no process restart.
func TestSessionSource_RecoversFromARealCLILoginOnDisk(t *testing.T) {
	original := common.SessionBaseDir
	common.SessionBaseDir = t.TempDir()
	t.Cleanup(func() { common.SessionBaseDir = original })

	var seenTokens []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		seenTokens = append(seenTokens, body.RefreshToken)

		if body.RefreshToken == "refresh-old" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"token":"final-access","refresh_token":"refresh-final","user_id":"11111111-1111-1111-1111-111111111111","username":"admin","roles":["admin"],"expires_at":%q}`,
			time.Now().Add(time.Hour).Format(time.RFC3339Nano))
	}))
	defer srv.Close()

	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	// A `rocketvault users login` ran once, before the MCP subprocess started.
	old := &common.SessionCache{
		Token: "old-access", RefreshToken: "refresh-old",
		UserID: userID, Username: "admin", Roles: []string{"admin"},
		ExpiresAt: time.Now().Add(-time.Minute), ServerKey: common.LocalServerKey,
	}
	require.NoError(t, common.SaveSession(old))

	// The MCP subprocess starts here, reading `old` at construction --
	// exactly what rocketvault mcp does in cmd/mcp.go via
	// resolveMCPTokenSource -> vaultapi.NewSessionSource.
	src, err := NewSessionSource(SessionConfig{BaseURL: srv.URL, HTTPClient: srv.Client()})
	require.NoError(t, err)

	// `rocketvault users login` runs again, in a different process, while
	// the MCP subprocess above keeps running.
	fresh := &common.SessionCache{
		Token: "fresh-access", RefreshToken: "refresh-fresh",
		UserID: userID, Username: "admin", Roles: []string{"admin"},
		ExpiresAt: time.Now().Add(-time.Minute), ServerKey: common.LocalServerKey,
	}
	require.NoError(t, common.SaveSession(fresh))

	// The subprocess's very next tool call -- no restart -- must succeed.
	tok, err := src.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "final-access", tok)
	require.Equal(t, []string{"refresh-old", "refresh-fresh"}, seenTokens,
		"the stale in-memory token is tried first, then the one the second login wrote to disk")
}
