package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteMCPCheckReport_ListsTheEssentials(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{
		BaseURL:     "https://vault.example.com",
		Identity:    `service account "mcp-agent"`,
		Vault:       "prod",
		Reachable:   true,
		VaultCount:  3,
		Tools:       []string{"list_secrets", "get_secret"},
		Tiers:       []string{"read"},
		MaxResults:  50,
		ValuesShown: false,
	})

	rendered := out.String()
	require.Contains(t, rendered, "https://vault.example.com")
	require.Contains(t, rendered, "mcp-agent")
	require.Contains(t, rendered, "prod")
	require.Contains(t, rendered, "list_secrets")
	require.Contains(t, rendered, "get_secret")
}

func TestWriteMCPCheckReport_StatesTheToolCount(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{
		Tools: []string{"a", "b", "c"},
		Tiers: []string{"read"},
	})

	require.Contains(t, out.String(), "3",
		"the count is what an operator checks against their expectation")
}

func TestWriteMCPCheckReport_SaysWhenValuesAreWithheld(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{Tools: []string{"a"}, ValuesShown: false})

	rendered := strings.ToLower(out.String())
	require.Contains(t, rendered, "secret values")
	require.Contains(t, rendered, "not")
}

func TestWriteMCPCheckReport_SaysWhenValuesAreExposed(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{Tools: []string{"a"}, ValuesShown: true})

	require.Contains(t, strings.ToLower(out.String()), "secret values can be returned",
		"enabling disclosure is worth stating plainly, not implying")
}

func TestWriteMCPCheckReport_WarnsWhenActingAsASession(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{
		Identity:  `cached session for "admin"`,
		IsSession: true,
		Tools:     []string{"a"},
	})

	rendered := out.String()
	require.Contains(t, rendered, "audit log",
		"under a session the agent's actions are indistinguishable from the operator's")
	require.Contains(t, rendered, "require_service_account")
}

func TestWriteMCPCheckReport_NoWarningForAServiceAccount(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{
		Identity:  `service account "mcp-agent"`,
		IsSession: false,
		Tools:     []string{"a"},
	})

	require.NotContains(t, out.String(), "require_service_account")
}

func TestWriteMCPCheckReport_ReportsUnreachability(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{
		BaseURL:   "https://vault.example.com",
		Reachable: false,
		Failure:   "connection refused",
		Tools:     []string{"a"},
	})

	rendered := out.String()
	require.Contains(t, rendered, "connection refused")
	require.Contains(t, strings.ToUpper(rendered), "FAIL")
}

func TestWriteMCPCheckReport_NeverIncludesASecret(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{
		Identity: `service account "mcp-agent"`,
		Tools:    []string{"a"},
	})

	require.NotContains(t, out.String(), "client_secret")
	require.NotContains(t, out.String(), "ROCKETVAULT_MCP_CLIENT_SECRET=")
}

func TestWriteMCPCheckReport_ListsEnabledTiers(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{
		Tools: []string{"a"},
		Tiers: []string{"read", "write"},
	})

	rendered := out.String()
	require.Contains(t, rendered, "read")
	require.Contains(t, rendered, "write")
}

func TestWriteMCPCheckReport_ToolsAreListedOnePerLine(t *testing.T) {
	var out bytes.Buffer
	writeMCPCheckReport(&out, mcpCheckReport{Tools: []string{"alpha", "beta", "gamma"}})

	for _, name := range []string{"alpha", "beta", "gamma"} {
		require.Contains(t, out.String(), name)
	}
	require.GreaterOrEqual(t, strings.Count(out.String(), "\n"), 3,
		"a scannable list beats a comma-joined blob")
}
