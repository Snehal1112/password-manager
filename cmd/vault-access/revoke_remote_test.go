package vaultaccess

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cliclient"
)

func TestRevokeRemote_DeletesByAssignmentID(t *testing.T) {
	id := uuid.New()
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cmd, out := remoteTestCmd(t, "payments")

	require.NoError(t, runRevokeRemote(cmd, remoteTestClient(t, srv), &cliclient.Target{Server: srv.URL}, id.String()))
	assert.Equal(t, "/api/v1/vaults/payments/role-assignments/"+id.String(), gotPath)
	assert.Equal(t, http.MethodDelete, gotMethod)
	assert.Contains(t, out.String(), "revoked assignment "+id.String())
}

func TestRevokeRemote_RejectsPrincipalName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("no request should be made for a non-UUID argument")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cmd, _ := remoteTestCmd(t, "payments")

	err := runRevokeRemote(cmd, remoteTestClient(t, srv), &cliclient.Target{Server: srv.URL}, "alice")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "assignment id")
}
