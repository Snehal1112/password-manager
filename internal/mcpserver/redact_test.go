package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/vaultapi"
)

const secretPlaintext = "hunter2-super-secret"

// serverAllowingValues builds a server with allow_secret_values set as given.
func serverAllowingValues(t *testing.T, allow bool) *Server {
	t.Helper()
	cfg := testConfig()
	cfg.AllowSecretValues = allow
	s, err := New(Deps{Config: cfg, Logger: discardLogger(), Version: "test"})
	require.NoError(t, err)
	return s
}

func TestMayDiscloseValues_TracksTheFlag(t *testing.T) {
	require.False(t, serverAllowingValues(t, false).MayDiscloseValues())
	require.True(t, serverAllowingValues(t, true).MayDiscloseValues())
}

func TestDiscloseValue_RedactsWhenDisabled(t *testing.T) {
	s := serverAllowingValues(t, false)

	got, disclosed := s.discloseValue(vaultapi.SecretValue(secretPlaintext))
	require.False(t, disclosed)
	require.Equal(t, RedactedPlaceholder, got)
	require.NotContains(t, got, secretPlaintext)
}

func TestDiscloseValue_RevealsWhenEnabled(t *testing.T) {
	s := serverAllowingValues(t, true)

	got, disclosed := s.discloseValue(vaultapi.SecretValue(secretPlaintext))
	require.True(t, disclosed)
	require.Equal(t, secretPlaintext, got)
}

func TestDiscloseValue_EmptyValueStillRedactsWhenDisabled(t *testing.T) {
	s := serverAllowingValues(t, false)

	got, disclosed := s.discloseValue(vaultapi.SecretValue(""))
	require.False(t, disclosed)
	require.Equal(t, RedactedPlaceholder, got,
		"an empty value must not be distinguishable from a populated one")
}

func TestDiscloseValue_EmptyValueRevealsAsEmptyWhenEnabled(t *testing.T) {
	s := serverAllowingValues(t, true)

	got, disclosed := s.discloseValue(vaultapi.SecretValue(""))
	require.True(t, disclosed)
	require.Empty(t, got)
}

func TestRedaction_ValueNeverAppearsInAnyResponseByteWhenDisabled(t *testing.T) {
	s := serverAllowingValues(t, false)

	type valueOut struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	registerIf(s, TierRead, "leaky", "Tries to return a value.", Annotations{ReadOnly: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, valueOut, error) {
			rendered, _ := s.discloseValue(vaultapi.SecretValue(secretPlaintext))
			return nil, valueOut{Name: "db-password", Value: rendered}, nil
		})

	cs := connect(t, s)
	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "leaky", Arguments: map[string]any{"message": "x"},
	})
	require.NoError(t, err)

	// Sweep the entire serialized result, not just the field we expect.
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), secretPlaintext,
		"no byte of any response may carry the plaintext when disclosure is off")
	require.Contains(t, string(encoded), RedactedPlaceholder)
}

func TestRedaction_ValueAppearsOnlyWhenExplicitlyEnabled(t *testing.T) {
	s := serverAllowingValues(t, true)

	type valueOut struct {
		Value string `json:"value"`
	}
	registerIf(s, TierRead, "reveal", "Returns a value.", Annotations{ReadOnly: true},
		func(ctx context.Context, req *mcp.CallToolRequest, in pingIn) (*mcp.CallToolResult, valueOut, error) {
			rendered, _ := s.discloseValue(vaultapi.SecretValue(secretPlaintext))
			return nil, valueOut{Value: rendered}, nil
		})

	cs := connect(t, s)
	result, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "reveal", Arguments: map[string]any{"message": "x"},
	})
	require.NoError(t, err)

	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.Contains(t, string(encoded), secretPlaintext)
}

func TestRedaction_PlaceholderMatchesVaultapi(t *testing.T) {
	// Two placeholders that drift apart would make output inconsistent
	// depending on which layer redacted.
	require.Equal(t, vaultapi.SecretValue("anything").String(), RedactedPlaceholder)
}
