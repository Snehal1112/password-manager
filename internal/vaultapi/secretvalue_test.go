package vaultapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const plaintext = "hunter2-super-secret"

func TestSecretValue_RevealReturnsPlaintext(t *testing.T) {
	v := SecretValue(plaintext)
	require.Equal(t, plaintext, v.Reveal())
}

func TestSecretValue_StringRedacts(t *testing.T) {
	v := SecretValue(plaintext)
	require.Equal(t, "[REDACTED]", v.String())
	require.NotContains(t, v.String(), plaintext)
}

func TestSecretValue_VerbFormattingRedacts(t *testing.T) {
	v := SecretValue(plaintext)
	for _, format := range []string{"%s", "%v", "%q", "%#v", "%+v"} {
		rendered := fmt.Sprintf(format, v)
		require.NotContains(t, rendered, plaintext, "format %s leaked the value", format)
	}
}

func TestSecretValue_MarshalJSONRedacts(t *testing.T) {
	v := SecretValue(plaintext)
	encoded, err := json.Marshal(v)
	require.NoError(t, err)
	require.JSONEq(t, `"[REDACTED]"`, string(encoded))
}

func TestSecretValue_RedactsInsideAStruct(t *testing.T) {
	type payload struct {
		Name  string      `json:"name"`
		Value SecretValue `json:"value"`
	}
	encoded, err := json.Marshal(payload{Name: "db-password", Value: SecretValue(plaintext)})
	require.NoError(t, err)
	require.NotContains(t, string(encoded), plaintext,
		"a value must not leak when its containing struct is marshalled")
	require.Contains(t, string(encoded), "db-password")
}

func TestSecretValue_RedactsWhenLoggedViaPrintf(t *testing.T) {
	var sb strings.Builder
	v := SecretValue(plaintext)
	_, _ = fmt.Fprintf(&sb, "fetched secret value=%v extra=%#v", v, v)
	require.NotContains(t, sb.String(), plaintext)
	require.Equal(t, 2, strings.Count(sb.String(), "[REDACTED]"))
}

func TestSecretValue_ZeroClearsTheValue(t *testing.T) {
	v := SecretValue(plaintext)
	v.Zero()
	require.Empty(t, v.Reveal())
}

func TestSecretValue_EmptyRevealsEmpty(t *testing.T) {
	var v SecretValue
	require.Empty(t, v.Reveal())
	require.Equal(t, "[REDACTED]", v.String(),
		"an empty value still renders as redacted, so its emptiness is not disclosed")
}
