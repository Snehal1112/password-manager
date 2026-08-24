package vaultapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// writeProbe records what a mutating request sent.
type writeProbe struct {
	method string
	path   string
	body   map[string]any
	calls  int
}

// probeServer serves list and write routes, recording the write.
func probeServer(t *testing.T, listBody string, status int, response string) (*httptest.Server, *writeProbe) {
	t.Helper()

	probe := &writeProbe{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(listBody))
			return
		}

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

func TestSetSecret_CreatesWhenTheNameIsUnknown(t *testing.T) {
	srv, probe := probeServer(t, `{"secrets":[],"total":0}`, http.StatusCreated,
		`{"id":"`+dbSecretID+`","name":"db-password","version":1}`)

	c := newClientForTest(t, srv)
	got, created, err := c.SetSecret(context.Background(), "prod", SetSecretRequest{
		Name: "db-password", Value: SecretValue("hunter2"),
	})
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, "db-password", got.Name)

	require.Equal(t, http.MethodPost, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/secrets", probe.path)
	require.Equal(t, "hunter2", probe.body["value"])
}

func TestSetSecret_UpdatesWhenTheNameExists(t *testing.T) {
	listBody := `{"secrets":[{"id":"` + dbSecretID + `","name":"db-password"}],"total":1}`
	srv, probe := probeServer(t, listBody, http.StatusOK,
		`{"id":"`+dbSecretID+`","name":"db-password","version":4}`)

	c := newClientForTest(t, srv)
	got, created, err := c.SetSecret(context.Background(), "prod", SetSecretRequest{
		Name: "db-password", Value: SecretValue("new-value"),
	})
	require.NoError(t, err)
	require.False(t, created, "an existing name is an update, not a create")
	require.Equal(t, 4, got.Version)

	require.Equal(t, http.MethodPut, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/secrets/"+dbSecretID, probe.path)
}

func TestSetSecret_SendsOptionalFields(t *testing.T) {
	expires := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	enabled := true

	srv, probe := probeServer(t, `{"secrets":[],"total":0}`, http.StatusCreated,
		`{"id":"`+dbSecretID+`","name":"db-password"}`)

	c := newClientForTest(t, srv)
	_, _, err := c.SetSecret(context.Background(), "prod", SetSecretRequest{
		Name:        "db-password",
		Value:       SecretValue("hunter2"),
		Tags:        []string{"prod", "db"},
		ContentType: "text/plain",
		Enabled:     &enabled,
		ExpiresAt:   &expires,
	})
	require.NoError(t, err)

	require.Equal(t, "text/plain", probe.body["content_type"])
	require.Equal(t, true, probe.body["enabled"])
	require.NotNil(t, probe.body["expires_at"])
	require.Len(t, probe.body["tags"], 2)
}

func TestSetSecret_UpdateWithoutAValueOmitsIt(t *testing.T) {
	// Changing only the expiry must not require knowing the current value.
	listBody := `{"secrets":[{"id":"` + dbSecretID + `","name":"db-password"}],"total":1}`
	srv, probe := probeServer(t, listBody, http.StatusOK, `{"id":"`+dbSecretID+`","name":"db-password"}`)

	expires := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	c := newClientForTest(t, srv)
	_, created, err := c.SetSecret(context.Background(), "prod", SetSecretRequest{
		Name: "db-password", ExpiresAt: &expires,
	})
	require.NoError(t, err)
	require.False(t, created)

	_, present := probe.body["value"]
	require.False(t, present, "an update with no value must not send an empty one")
}

func TestSetSecret_CreateRequiresAValue(t *testing.T) {
	srv, probe := probeServer(t, `{"secrets":[],"total":0}`, http.StatusCreated, `{}`)

	c := newClientForTest(t, srv)
	_, _, err := c.SetSecret(context.Background(), "prod", SetSecretRequest{Name: "new-secret"})
	require.ErrorContains(t, err, "value")
	require.Zero(t, probe.calls, "a request that cannot succeed must not be sent")
}

func TestSetSecret_RequiresANameAndVault(t *testing.T) {
	srv, _ := probeServer(t, `{"secrets":[],"total":0}`, http.StatusCreated, `{}`)
	c := newClientForTest(t, srv)

	_, _, err := c.SetSecret(context.Background(), "", SetSecretRequest{Name: "x", Value: "v"})
	require.ErrorContains(t, err, "vault is required")

	_, _, err = c.SetSecret(context.Background(), "prod", SetSecretRequest{Value: "v"})
	require.ErrorContains(t, err, "name is required")
}

func TestSetSecret_IsAttemptedExactlyOnce(t *testing.T) {
	srv, probe := probeServer(t, `{"secrets":[],"total":0}`, http.StatusInternalServerError, `{}`)

	c := newClientForTest(t, srv)
	_, _, err := c.SetSecret(context.Background(), "prod", SetSecretRequest{
		Name: "db-password", Value: SecretValue("hunter2"),
	})
	require.Error(t, err)
	require.Equal(t, 1, probe.calls,
		"retrying a lost-response create would duplicate the secret")
}

func TestSetSecret_ErrorNeverContainsTheValue(t *testing.T) {
	srv, _ := probeServer(t, `{"secrets":[],"total":0}`, http.StatusForbidden,
		`{"message":"denied while writing hunter2-super-secret"}`)

	c := newClientForTest(t, srv)
	_, _, err := c.SetSecret(context.Background(), "prod", SetSecretRequest{
		Name: "db-password", Value: SecretValue("hunter2-super-secret"),
	})
	require.Error(t, err)
	require.NotContains(t, err.Error(), "hunter2-super-secret")
}

func TestSetSecretRequest_MarshalsWithoutLeakingTheValue(t *testing.T) {
	// The request struct itself must be safe to log or marshal.
	req := SetSecretRequest{Name: "db-password", Value: SecretValue("hunter2-super-secret")}

	encoded, err := json.Marshal(req)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "hunter2-super-secret",
		"a request carrying plaintext must redact like a response does")
}

func TestSetSecret_ForbiddenResolveDoesNotBecomeACreate(t *testing.T) {
	var writeCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		writeCalls++
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := newClientForTest(t, srv)
	_, _, err := c.SetSecret(context.Background(), "prod", SetSecretRequest{
		Name: "db-password", Value: SecretValue("hunter2"),
	})

	require.Error(t, err)
	require.Zero(t, writeCalls,
		"a denied listing must not be read as 'the secret does not exist' and become a create")

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, KindForbidden, apiErr.Kind)
}
