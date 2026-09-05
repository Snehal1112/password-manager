package vaultaccess

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/cliclient"
)

func TestListRemote_PrintsSameColumnsAsLocal(t *testing.T) {
	id, principalID := uuid.New(), uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/vaults/payments/role-assignments", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"role_assignments": []map[string]any{{
				"id": id.String(), "principal_id": principalID.String(),
				"principal_type": "user", "role": "Key Vault Administrator",
				"vault_name": "payments", "created_at": "2026-09-03T10:00:00Z",
			}},
			"total": 1,
		})
	}))
	defer srv.Close()

	cmd, out := remoteTestCmd(t, "payments")

	require.NoError(t, runListRemote(cmd, remoteTestClient(t, srv), &cliclient.Target{Server: srv.URL}))

	got := out.String()
	assert.Contains(t, got, "ASSIGNMENT-ID")
	assert.Contains(t, got, "ROLE")
	assert.Contains(t, got, "PRINCIPAL-ID")
	assert.Contains(t, got, id.String())
	assert.Contains(t, got, "Key Vault Administrator")
}
