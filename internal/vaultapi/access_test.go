package vaultapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

const assignmentID = "7d4804e0-4f89-11d3-9a0c-0305e82c3701"

func TestListRoleAssignments_UsesVaultScopedRoute(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"role_assignments":[
			{"id":"` + assignmentID + `","principal_id":"` + dbSecretID + `",
			 "principal_username":"mcp-agent","principal_type":"service_account",
			 "role":"Key Vault Secrets User","vault_id":"` + prodVaultID + `",
			 "vault_name":"prod","created_at":"2026-08-01T00:00:00Z"}
		],"total":1}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListRoleAssignments(context.Background(), "prod", 50)
	require.NoError(t, err)
	require.Equal(t, "/api/v1/vaults/prod/role-assignments", gotPath)
	require.False(t, truncated)
	require.Len(t, got, 1)
	require.Equal(t, "Key Vault Secrets User", got[0].Role)
	require.Equal(t, "mcp-agent", got[0].PrincipalUsername)
	require.Equal(t, "service_account", got[0].PrincipalType)
	require.Equal(t, uuid.MustParse(assignmentID), got[0].ID)
	require.Equal(t, "prod", got[0].VaultName)
}

func TestListRoleAssignments_TruncatesAtLimitAndReportsIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"role_assignments":[
			{"id":"` + assignmentID + `","principal_id":"` + dbSecretID + `","role":"Key Vault Reader"},
			{"id":"` + apiSecretID + `","principal_id":"` + dbSecretID + `","role":"Key Vault Crypto User"},
			{"id":"` + signKeyID + `","principal_id":"` + dbSecretID + `","role":"Key Vault Secrets User"}
		],"total":3}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListRoleAssignments(context.Background(), "prod", 2)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.True(t, truncated)
}

func TestListRoleAssignments_EmptyIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"role_assignments":[],"total":0}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListRoleAssignments(context.Background(), "prod", 50)
	require.NoError(t, err)
	require.Empty(t, got)
	require.False(t, truncated)
}

func TestListRoleAssignments_RequiresVault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	_, _, err := newClientForTest(t, srv).ListRoleAssignments(context.Background(), "", 50)
	require.ErrorContains(t, err, "vault is required")
}

func TestListRoleAssignments_ForbiddenHintNamesTheDataAccessAdminRole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, _, err := newClientForTest(t, srv).ListRoleAssignments(context.Background(), "prod", 50)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Contains(t, apiErr.Hint, "Key Vault Data Access Administrator",
		"this is the one role grantable per vault that permits managing assignments")
}
