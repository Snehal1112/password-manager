package vaultapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// vaultWriteServer records the create-vault request.
func vaultWriteServer(t *testing.T, status int, response string) (*httptest.Server, *writeProbe) {
	t.Helper()

	probe := &writeProbe{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probe.calls++
		probe.method, probe.path = r.Method, r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&probe.body)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(srv.Close)
	return srv, probe
}

func TestCreateVault_PostsToTheUnscopedRoute(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated,
		`{"id":"`+prodVaultID+`","name":"prod","enabled":true,"retention_days":90}`)

	c := newClientForTest(t, srv)
	got, err := c.CreateVault(context.Background(), CreateVaultRequest{Name: "prod"})
	require.NoError(t, err)

	require.Equal(t, http.MethodPost, probe.method)
	require.Equal(t, "/api/v1/vaults", probe.path)
	require.Equal(t, "prod", got.Name)
	require.Equal(t, 90, got.RetentionDays)
}

func TestCreateVault_OmitsUnsetOptionalFields(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{"id":"`+prodVaultID+`","name":"prod"}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateVault(context.Background(), CreateVaultRequest{Name: "prod"})
	require.NoError(t, err)

	for _, field := range []string{"enabled", "purge_protection", "retention_days"} {
		_, present := probe.body[field]
		require.False(t, present,
			"omitting %q must mean 'server default', not an explicit zero value", field)
	}
}

func TestCreateVault_SendsExplicitOptionalFields(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{"id":"`+prodVaultID+`","name":"prod"}`)

	enabled, protect, retention := true, true, 30
	c := newClientForTest(t, srv)
	_, err := c.CreateVault(context.Background(), CreateVaultRequest{
		Name:            "prod",
		Enabled:         &enabled,
		PurgeProtection: &protect,
		RetentionDays:   &retention,
		Tags:            map[string]string{"env": "production"},
	})
	require.NoError(t, err)

	require.Equal(t, true, probe.body["enabled"])
	require.Equal(t, true, probe.body["purge_protection"])
	require.EqualValues(t, 30, probe.body["retention_days"])
	require.NotNil(t, probe.body["tags"])
}

func TestCreateVault_ExplicitFalseIsSentNotOmitted(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{"id":"`+prodVaultID+`","name":"prod"}`)

	protect := false
	c := newClientForTest(t, srv)
	_, err := c.CreateVault(context.Background(), CreateVaultRequest{
		Name: "prod", PurgeProtection: &protect,
	})
	require.NoError(t, err)

	value, present := probe.body["purge_protection"]
	require.True(t, present, "an explicit false is a different statement from silence")
	require.Equal(t, false, value)
}

func TestCreateVault_RequiresAName(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusCreated, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateVault(context.Background(), CreateVaultRequest{})
	require.ErrorContains(t, err, "name is required")
	require.Zero(t, probe.calls)
}

func TestCreateVault_IsAttemptedExactlyOnce(t *testing.T) {
	srv, probe := vaultWriteServer(t, http.StatusInternalServerError, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateVault(context.Background(), CreateVaultRequest{Name: "prod"})
	require.Error(t, err)
	require.Equal(t, 1, probe.calls)
}

func TestCreateVault_ConflictIsTypedAsSuch(t *testing.T) {
	srv, _ := vaultWriteServer(t, http.StatusConflict, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateVault(context.Background(), CreateVaultRequest{Name: "prod"})

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, KindConflict, apiErr.Kind,
		"a duplicate vault name is a conflict the caller can explain")
}
