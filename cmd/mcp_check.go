/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"rocketvault/config"
	"rocketvault/internal/mcpserver"
)

// mcpCheckReport is what --check prints.
type mcpCheckReport struct {
	BaseURL  string
	Identity string
	// IsSession reports that the identity is a cached CLI session rather
	// than a service account.
	IsSession bool
	Vault     string

	// Reachable and Failure record the live connectivity probe.
	Reachable  bool
	VaultCount int
	Failure    string

	Tools       []string
	Tiers       []string
	MaxResults  int
	ValuesShown bool
}

// writeMCPCheckReport renders the report.
//
// Tools are listed one per line rather than comma-joined: an operator is
// checking this against an expectation, and a scannable list makes a missing
// or unexpected entry obvious.
func writeMCPCheckReport(w io.Writer, report mcpCheckReport) {
	fmt.Fprintf(w, "RocketVault MCP server preflight\n\n")

	fmt.Fprintf(w, "  Server:    %s\n", report.BaseURL)
	fmt.Fprintf(w, "  Identity:  %s\n", report.Identity)
	fmt.Fprintf(w, "  Vault:     %s\n", report.Vault)

	if report.Reachable {
		fmt.Fprintf(w, "  Reachable: yes (%d vault(s) visible)\n", report.VaultCount)
	} else {
		fmt.Fprintf(w, "  Reachable: FAIL - %s\n", report.Failure)
	}

	fmt.Fprintf(w, "\n  Enabled tiers: %s\n", strings.Join(report.Tiers, ", "))
	fmt.Fprintf(w, "  Max results per list: %d\n", report.MaxResults)

	if report.ValuesShown {
		fmt.Fprintf(w, "  Secret values CAN be returned to the model (allow_secret_values is on).\n")
	} else {
		fmt.Fprintf(w, "  Secret values are not returned to the model.\n")
	}

	// Under a session the agent acts as the operator, so its actions are
	// indistinguishable from theirs in the audit log. That is worth saying at
	// setup time rather than leaving in a document.
	if report.IsSession {
		fmt.Fprintf(w, "\n  Note: this server acts as your own logged-in user, so its actions\n")
		fmt.Fprintf(w, "  are indistinguishable from yours in the audit log. For anything\n")
		fmt.Fprintf(w, "  beyond local use, configure a service account and set\n")
		fmt.Fprintf(w, "  mcp.require_service_account.\n")
	}

	fmt.Fprintf(w, "\n  Exposed tools (%d):\n", len(report.Tools))
	for _, name := range report.Tools {
		fmt.Fprintf(w, "    %s\n", name)
	}
}

// loadMCPConfigForCheck re-reads the configuration for the report. It is
// already known valid, since buildMCPServer loaded it first.
func loadMCPConfigForCheck() (config.MCPConfig, error) {
	return config.LoadMCPConfig()
}

// runMCPCheck validates the configuration and prints what would be exposed.
//
// It reuses the server built by the normal startup path, so it checks the
// real configuration rather than a parallel approximation that could drift.
//
// The report goes to stdout. That is safe only because --check serves no
// session: no protocol stream exists to corrupt.
func runMCPCheck(cmd *cobra.Command, server *mcpserver.Server, identity string) error {
	cfg, err := loadMCPConfigForCheck()
	if err != nil {
		return err
	}

	report := mcpCheckReport{
		BaseURL:     server.BaseURL(),
		Identity:    identity,
		IsSession:   strings.HasPrefix(identity, "cached session"),
		Vault:       cfg.Vault,
		Tools:       server.RegisteredTools(),
		Tiers:       server.EnabledTiers(),
		MaxResults:  cfg.MaxResults,
		ValuesShown: cfg.AllowSecretValues,
	}

	// One live call proves the credentials work. ListVaults is the right
	// probe: every identity may attempt it, it needs no arguments, and its
	// failures are the ones worth telling apart -- unreachable server, bad
	// credentials, or a principal with no grants.
	vaults, _, probeErr := server.ProbeVaults(cmd.Context())
	if probeErr != nil {
		report.Failure = probeErr.Error()
	} else {
		report.Reachable = true
		report.VaultCount = len(vaults)
	}

	writeMCPCheckReport(os.Stdout, report)

	if !report.Reachable {
		// Exit non-zero so the check is usable in a script.
		return fmt.Errorf("preflight failed: the server could not be reached with this identity")
	}
	return nil
}
