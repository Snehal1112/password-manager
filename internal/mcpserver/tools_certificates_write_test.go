package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateCertificate_IsAbsentWithoutAllowWrite(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, testConfig())
	registerCertificatesWriteTools(s)

	require.Empty(t, s.RegisteredTools())
}

func TestCreateCertificate_IssuesAgainstAnExistingKey(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"tls-key"}]}`,
	})
	f.writeResponse = `{"id":"` + tlsCertUUID + `","name":"tls-cert","auto_renew":true,"renewal_days":30}`
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	var got createCertificateResult
	structured(t, callTool(t, s, "create_certificate", map[string]any{
		"name": "tls-cert", "key_name": "tls-key", "validity_days": 365,
		"auto_renew": true, "renewal_days": 30,
	}), &got)

	require.Equal(t, "tls-cert", got.Name)
	require.True(t, got.AutoRenew)
	require.Equal(t, signKeyUUID, f.lastWriteBody["key_id"])
}

func TestCreateCertificate_DescriptionSaysAKeyIsRequired(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "create_certificate" {
			require.Contains(t, tool.Description, "existing key",
				"a model asked for a TLS certificate will otherwise try this without one")
			require.Contains(t, tool.Description, "create_key")
			return
		}
	}
	t.Fatal("create_certificate was not registered")
}

func TestCreateCertificate_UnknownKeyIsActionable(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"tls-key"}]}`,
	})
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	result := callTool(t, s, "create_certificate", map[string]any{
		"name": "tls-cert", "key_name": "no-such-key", "validity_days": 365,
	})
	require.True(t, result.IsError)
	require.Contains(t, renderContent(result), "no keys named")
}

func TestCreateCertificate_RequiresNameKeyAndValidity(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	require.True(t, callTool(t, s, "create_certificate", map[string]any{
		"key_name": "k", "validity_days": 365}).IsError)
	require.True(t, callTool(t, s, "create_certificate", map[string]any{
		"name": "c", "validity_days": 365}).IsError)
	require.True(t, callTool(t, s, "create_certificate", map[string]any{
		"name": "c", "key_name": "k"}).IsError)
}

func TestCreateCertificate_ReturnsNoPrivateMaterial(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/keys": `{"keys":[{"id":"` + signKeyUUID + `","name":"tls-key"}]}`,
	})
	f.writeResponse = `{"id":"` + tlsCertUUID + `","name":"tls-cert",
		"private_key":"-----BEGIN PRIVATE KEY-----LEAKED"}`
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	result := callTool(t, s, "create_certificate", map[string]any{
		"name": "tls-cert", "key_name": "tls-key", "validity_days": 365,
	})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "LEAKED")
}

func TestSetCertificatePolicy_ReplacesThePolicy(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/certificates": `{"certificates":[{"id":"` + tlsCertUUID + `","name":"tls-cert"}]}`,
	})
	f.writeResponse = `{"certificate_id":"` + tlsCertUUID + `","validity_months":12,"key_type":"RSA",
		"key_size":2048,"subject":"CN=example.com","auto_renew":true,"days_before_expiry":30}`
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	var got setCertificatePolicyResult
	structured(t, callTool(t, s, "set_certificate_policy", map[string]any{
		"name": "tls-cert", "validity_months": 12, "key_type": "RSA", "key_size": 2048,
		"subject": "CN=example.com", "auto_renew": true, "days_before_expiry": 30,
	}), &got)

	require.Equal(t, 12, got.ValidityMonths)
	// got.Subject round-tripped through structured()'s marshal/unmarshal, so
	// it still carries the delimiters Untrusted.MarshalJSON added: Text() has
	// no matching UnmarshalJSON to strip them back out. Contains rather than
	// Equal reflects that without asserting on the delimiter placement itself.
	require.Contains(t, got.Subject.Text(), "CN=example.com")
	require.Equal(t, "CN=example.com", f.lastWriteBody["subject"])
}

func TestSetCertificatePolicy_WrapsSubjectInTheResult(t *testing.T) {
	f := newFakeVault(t, map[string]string{
		"/api/v1/vaults/default/certificates": `{"certificates":[{"id":"` + tlsCertUUID + `","name":"tls-cert"}]}`,
	})
	f.writeResponse = `{"certificate_id":"` + tlsCertUUID + `","subject":"CN=example.com"}`
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	result := callTool(t, s, "set_certificate_policy", map[string]any{
		"name": "tls-cert", "validity_months": 12, "key_type": "RSA",
		"subject": "CN=example.com", "auto_renew": true, "days_before_expiry": 30,
	})
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "UNTRUSTED-VAULT-DATA",
		"the subject echoed back is still vault-resident free text")
}

func TestSetCertificatePolicy_KeySizeAndCurveStayOptional(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name != "set_certificate_policy" {
			continue
		}
		encoded, err := json.Marshal(tool.InputSchema)
		require.NoError(t, err)

		var schema map[string]any
		require.NoError(t, json.Unmarshal(encoded, &schema))

		required, _ := schema["required"].([]any)
		var names []string
		for _, item := range required {
			names = append(names, item.(string))
		}

		require.Contains(t, names, "validity_months")
		require.Contains(t, names, "subject")
		require.NotContains(t, names, "key_size",
			"exactly one of key_size and curve applies, so requiring both is unsatisfiable")
		require.NotContains(t, names, "curve")
		return
	}
	t.Fatal("set_certificate_policy was not registered")
}

func TestSetCertificatePolicy_DescriptionSaysItReplaces(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, writeConfig())
	registerCertificatesWriteTools(s)

	cs := connect(t, s)
	tools, err := cs.ListTools(context.Background(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "set_certificate_policy" {
			require.Contains(t, tool.Description, "Replaces")
			require.Contains(t, tool.Description, "get_certificate")
			return
		}
	}
	t.Fatal("set_certificate_policy was not registered")
}
