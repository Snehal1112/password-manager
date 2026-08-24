package vaultapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// certWriteServer serves the key list plus a certificate write.
func certWriteServer(t *testing.T, keysBody string, status int, response string) (*httptest.Server, *writeProbe) {
	t.Helper()

	probe := &writeProbe{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(keysBody))
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

const keysForCertBody = `{"keys":[{"id":"` + rsaKeyID + `","name":"tls-key"}]}`

func TestCreateCertificate_ResolvesTheKeyNameToAnID(t *testing.T) {
	srv, probe := certWriteServer(t, keysForCertBody, http.StatusCreated,
		`{"id":"`+tlsCertID+`","name":"tls-cert","auto_renew":true,"renewal_days":30}`)

	c := newClientForTest(t, srv)
	got, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "tls-cert", KeyName: "tls-key", ValidityDays: 365, AutoRenew: true, RenewalDays: 30,
	})
	require.NoError(t, err)

	require.Equal(t, http.MethodPost, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/certificates", probe.path)
	require.Equal(t, rsaKeyID, probe.body["key_id"],
		"the exported API takes a key name; the wire takes its id")
	require.Equal(t, "tls-cert", got.Name)
}

func TestCreateCertificate_AcceptsAKeyUUIDDirectly(t *testing.T) {
	srv, probe := certWriteServer(t, `{"keys":[]}`, http.StatusCreated,
		`{"id":"`+tlsCertID+`","name":"tls-cert"}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "tls-cert", KeyName: rsaKeyID, ValidityDays: 365,
	})
	require.NoError(t, err)
	require.Equal(t, rsaKeyID, probe.body["key_id"],
		"a UUID passes through resolution unchanged, so nothing is lost by taking names")
}

func TestCreateCertificate_SendsTheCoreFields(t *testing.T) {
	srv, probe := certWriteServer(t, keysForCertBody, http.StatusCreated,
		`{"id":"`+tlsCertID+`","name":"tls-cert"}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "tls-cert", KeyName: "tls-key", ValidityDays: 365,
		AutoRenew: true, RenewalDays: 30, Tags: []string{"edge"},
	})
	require.NoError(t, err)

	require.Equal(t, "tls-cert", probe.body["name"])
	require.EqualValues(t, 365, probe.body["validity_days"])
	require.Equal(t, true, probe.body["auto_renew"])
	require.EqualValues(t, 30, probe.body["renewal_days"])
	require.Len(t, probe.body["tags"], 1)
}

func TestCreateCertificate_ResolvesOptionalCAReferences(t *testing.T) {
	keysBody := `{"keys":[{"id":"` + rsaKeyID + `","name":"tls-key"},
		{"id":"` + dbSecretID + `","name":"ca-key"}]}`
	certsBody := `{"certificates":[{"id":"` + apiSecretID + `","name":"ca-cert"}]}`

	probe := &writeProbe{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/api/v1/vaults/prod/certificates" {
				_, _ = w.Write([]byte(certsBody))
				return
			}
			_, _ = w.Write([]byte(keysBody))
			return
		}
		probe.calls++
		probe.method, probe.path = r.Method, r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&probe.body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"` + tlsCertID + `","name":"tls-cert"}`))
	}))
	defer srv.Close()

	c := newClientForTest(t, srv)
	_, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "tls-cert", KeyName: "tls-key", ValidityDays: 365,
		CAKeyName: "ca-key", CACertName: "ca-cert",
	})
	require.NoError(t, err)

	require.Equal(t, dbSecretID, probe.body["ca_key_id"])
	require.Equal(t, apiSecretID, probe.body["ca_cert_id"])
}

func TestCreateCertificate_OmitsUnsetCAReferences(t *testing.T) {
	srv, probe := certWriteServer(t, keysForCertBody, http.StatusCreated,
		`{"id":"`+tlsCertID+`","name":"tls-cert"}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "tls-cert", KeyName: "tls-key", ValidityDays: 365,
	})
	require.NoError(t, err)

	for _, field := range []string{"ca_key_id", "ca_cert_id"} {
		_, present := probe.body[field]
		require.False(t, present, "an unset CA reference must be omitted, not sent empty")
	}
}

func TestCreateCertificate_UnknownKeyNameIsNotFound(t *testing.T) {
	srv, probe := certWriteServer(t, `{"keys":[]}`, http.StatusCreated, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "tls-cert", KeyName: "no-such-key", ValidityDays: 365,
	})
	require.ErrorIs(t, err, ErrResourceNotFound)
	require.Zero(t, probe.calls, "an unresolvable key must not produce a create call")
}

func TestCreateCertificate_RequiresVaultNameKeyAndValidity(t *testing.T) {
	srv, probe := certWriteServer(t, keysForCertBody, http.StatusCreated, `{}`)
	c := newClientForTest(t, srv)

	_, err := c.CreateCertificate(context.Background(), "", CreateCertificateRequest{
		Name: "c", KeyName: "tls-key", ValidityDays: 365})
	require.ErrorContains(t, err, "vault is required")

	_, err = c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		KeyName: "tls-key", ValidityDays: 365})
	require.ErrorContains(t, err, "name is required")

	_, err = c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "c", ValidityDays: 365})
	require.ErrorContains(t, err, "key")

	_, err = c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "c", KeyName: "tls-key"})
	require.ErrorContains(t, err, "validity")

	require.Zero(t, probe.calls)
}

func TestCreateCertificate_IsAttemptedExactlyOnce(t *testing.T) {
	srv, probe := certWriteServer(t, keysForCertBody, http.StatusInternalServerError, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "tls-cert", KeyName: "tls-key", ValidityDays: 365,
	})
	require.Error(t, err)
	require.Equal(t, 1, probe.calls)
}

func TestCreateCertificate_CarriesNoPrivateMaterial(t *testing.T) {
	srv, _ := certWriteServer(t, keysForCertBody, http.StatusCreated,
		`{"id":"`+tlsCertID+`","name":"tls-cert","private_key":"-----BEGIN PRIVATE KEY-----LEAKED"}`)

	c := newClientForTest(t, srv)
	got, err := c.CreateCertificate(context.Background(), "prod", CreateCertificateRequest{
		Name: "tls-cert", KeyName: "tls-key", ValidityDays: 365,
	})
	require.NoError(t, err)

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "LEAKED")
}
