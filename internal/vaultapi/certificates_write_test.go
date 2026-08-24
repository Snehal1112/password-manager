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

const certsForPolicyBody = `{"certificates":[{"id":"` + tlsCertID + `","name":"tls-cert"}]}`

func TestUpsertCertificatePolicy_PutsToThePolicyRoute(t *testing.T) {
	srv, probe := certWriteServer(t, certsForPolicyBody, http.StatusOK,
		`{"certificate_id":"`+tlsCertID+`","validity_months":12,"key_type":"RSA","key_size":2048,
		  "subject":"CN=example.com","auto_renew":true,"days_before_expiry":30}`)

	c := newClientForTest(t, srv)
	got, err := c.UpsertCertificatePolicy(context.Background(), "prod", "tls-cert",
		SetCertificatePolicyRequest{
			ValidityMonths: 12, KeyType: "RSA", KeySize: 2048,
			Subject: "CN=example.com", AutoRenew: true, DaysBeforeExpiry: 30,
		})
	require.NoError(t, err)

	require.Equal(t, http.MethodPut, probe.method)
	require.Equal(t, "/api/v1/vaults/prod/certificates/"+tlsCertID+"/policy", probe.path)
	require.Equal(t, "CN=example.com", got.Subject)
	require.Equal(t, 12, got.ValidityMonths)
}

func TestUpsertCertificatePolicy_SendsTheAlwaysPresentFields(t *testing.T) {
	srv, probe := certWriteServer(t, certsForPolicyBody, http.StatusOK,
		`{"certificate_id":"`+tlsCertID+`"}`)

	c := newClientForTest(t, srv)
	_, err := c.UpsertCertificatePolicy(context.Background(), "prod", "tls-cert",
		SetCertificatePolicyRequest{ValidityMonths: 12, KeyType: "RSA", Subject: "CN=example.com"})
	require.NoError(t, err)

	for _, field := range []string{"validity_months", "key_type", "subject", "auto_renew", "days_before_expiry"} {
		_, present := probe.body[field]
		require.True(t, present, "field %q must always be sent: this is a full replacement", field)
	}
}

func TestUpsertCertificatePolicy_OmitsKeySizeAndCurveWhenUnset(t *testing.T) {
	srv, probe := certWriteServer(t, certsForPolicyBody, http.StatusOK,
		`{"certificate_id":"`+tlsCertID+`"}`)

	c := newClientForTest(t, srv)
	_, err := c.UpsertCertificatePolicy(context.Background(), "prod", "tls-cert",
		SetCertificatePolicyRequest{ValidityMonths: 12, KeyType: "RSA", Subject: "CN=example.com"})
	require.NoError(t, err)

	for _, field := range []string{"key_size", "curve"} {
		_, present := probe.body[field]
		require.False(t, present, "only one of key_size and curve applies per key type")
	}
}

func TestUpsertCertificatePolicy_SendsSubjectVerbatim(t *testing.T) {
	srv, probe := certWriteServer(t, certsForPolicyBody, http.StatusOK,
		`{"certificate_id":"`+tlsCertID+`"}`)

	subject := "CN=example.com, OU=Platform, O=Example Ltd"
	c := newClientForTest(t, srv)
	_, err := c.UpsertCertificatePolicy(context.Background(), "prod", "tls-cert",
		SetCertificatePolicyRequest{ValidityMonths: 12, KeyType: "RSA", Subject: subject})
	require.NoError(t, err)

	require.Equal(t, subject, probe.body["subject"],
		"a distinguished name must survive intact; this layer does not reformat it")
}

func TestUpsertCertificatePolicy_UnknownCertificateIsNotFound(t *testing.T) {
	srv, probe := certWriteServer(t, `{"certificates":[]}`, http.StatusOK, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.UpsertCertificatePolicy(context.Background(), "prod", "no-such-cert",
		SetCertificatePolicyRequest{ValidityMonths: 12, KeyType: "RSA", Subject: "CN=x"})
	require.ErrorIs(t, err, ErrResourceNotFound)
	require.Zero(t, probe.calls)
}

func TestUpsertCertificatePolicy_RequiresVaultAndName(t *testing.T) {
	srv, probe := certWriteServer(t, certsForPolicyBody, http.StatusOK, `{}`)
	c := newClientForTest(t, srv)

	_, err := c.UpsertCertificatePolicy(context.Background(), "", "tls-cert", SetCertificatePolicyRequest{})
	require.ErrorContains(t, err, "vault is required")

	_, err = c.UpsertCertificatePolicy(context.Background(), "prod", "", SetCertificatePolicyRequest{})
	require.ErrorContains(t, err, "name is required")

	require.Zero(t, probe.calls)
}

func TestUpsertCertificatePolicy_IsAttemptedExactlyOnce(t *testing.T) {
	srv, probe := certWriteServer(t, certsForPolicyBody, http.StatusInternalServerError, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.UpsertCertificatePolicy(context.Background(), "prod", "tls-cert",
		SetCertificatePolicyRequest{ValidityMonths: 12, KeyType: "RSA", Subject: "CN=x"})
	require.Error(t, err)
	require.Equal(t, 1, probe.calls)
}

func TestUpsertCertificatePolicy_ForbiddenSurfacesTheCertificatesOfficerHint(t *testing.T) {
	srv, _ := certWriteServer(t, certsForPolicyBody, http.StatusForbidden, `{}`)

	c := newClientForTest(t, srv)
	_, err := c.UpsertCertificatePolicy(context.Background(), "prod", "tls-cert",
		SetCertificatePolicyRequest{ValidityMonths: 12, KeyType: "RSA", Subject: "CN=x"})

	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Contains(t, apiErr.Hint, "Key Vault Certificates Officer")
}
