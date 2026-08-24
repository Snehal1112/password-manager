package vaultapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

const prodVaultID = "6c3704e0-4f89-11d3-9a0c-0305e82c3601"

func TestListVaults_UsesTheUnscopedRoute(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vaults":[
			{"id":"` + prodVaultID + `","name":"prod","enabled":true,"purge_protection":true,
			 "retention_days":90,"created_at":"2026-08-01T00:00:00Z","tags":{"env":"production"}}
		],"total":1}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListVaults(context.Background(), false, 50)
	require.NoError(t, err)
	require.Equal(t, "/api/v1/vaults", gotPath)
	require.Empty(t, gotQuery, "include_deleted must be omitted when false")
	require.False(t, truncated)
	require.Len(t, got, 1)
	require.Equal(t, "prod", got[0].Name)
	require.True(t, got[0].PurgeProtection)
	require.Equal(t, 90, got[0].RetentionDays)
}

func TestListVaults_TagsAreAMapNotASlice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vaults":[
			{"id":"` + prodVaultID + `","name":"prod","tags":{"env":"production","team":"platform"}}
		],"total":1}`))
	}))
	defer srv.Close()

	got, _, err := newClientForTest(t, srv).ListVaults(context.Background(), false, 50)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"env": "production", "team": "platform"}, got[0].Tags)
}

func TestListVaults_IncludeDeletedSetsTheQueryParam(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vaults":[],"total":0}`))
	}))
	defer srv.Close()

	_, _, err := newClientForTest(t, srv).ListVaults(context.Background(), true, 50)
	require.NoError(t, err)
	require.Equal(t, "include_deleted=true", gotQuery)
}

func TestListVaults_StringTimestampsSurviveEmptyValues(t *testing.T) {
	// VaultResponse renders timestamps as strings. A live vault has no
	// deleted_at, and decoding that into a time.Time would fail.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vaults":[
			{"id":"` + prodVaultID + `","name":"prod","created_at":"2026-08-01T00:00:00Z","deleted_at":""}
		],"total":1}`))
	}))
	defer srv.Close()

	got, _, err := newClientForTest(t, srv).ListVaults(context.Background(), false, 50)
	require.NoError(t, err, "an empty timestamp string must not fail decoding")
	require.Equal(t, "2026-08-01T00:00:00Z", got[0].CreatedAt)
	require.Empty(t, got[0].DeletedAt)
}

func TestListVaults_TruncatesAtLimitAndReportsIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vaults":[
			{"id":"` + prodVaultID + `","name":"a"},
			{"id":"` + dbSecretID + `","name":"b"},
			{"id":"` + apiSecretID + `","name":"c"}
		],"total":3}`))
	}))
	defer srv.Close()

	got, truncated, err := newClientForTest(t, srv).ListVaults(context.Background(), false, 2)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.True(t, truncated)
}

func TestGetVault_AddressesByNameNotUUID(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + prodVaultID + `","name":"prod","enabled":true,"retention_days":90}`))
	}))
	defer srv.Close()

	got, err := newClientForTest(t, srv).GetVault(context.Background(), "prod")
	require.NoError(t, err)
	require.Equal(t, "/api/v1/vaults/prod", gotPath,
		"a vault's name is its identifier; there is no resolution step")
	require.Equal(t, uuid.MustParse(prodVaultID), got.ID)
	require.Equal(t, "prod", got.Name)
}

func TestGetVault_RequiresName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).GetVault(context.Background(), "")
	require.ErrorContains(t, err, "vault name is required")
}

func TestGetVault_UnknownVaultIsANotFoundAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := newClientForTest(t, srv).GetVault(context.Background(), "nope")
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, KindNotFound, apiErr.Kind)
}
