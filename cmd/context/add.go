package contextcli

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"

	"rocketvault/common"
)

// InitContextAdd wires the "add" subcommand onto parent (rocketvault
// context's --server flag is inherited from the persistent flag on rootCmd).
//
// The command is constructed fresh on every call rather than reused from a
// package-level var: a shared *cobra.Command's FlagSet panics on a repeat
// "flag redefined" if Init is invoked more than once in the same process
// (e.g. once per test function), which the package-level-var version of this
// command hit under `go test ./cmd/context/...`.
func InitContextAdd(parent *cobra.Command) *cobra.Command {
	addCmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Save a named remote server context",
		Long: `Save a named context: a remote server URL, plus an optional default
username and vault. Overwrites any existing context with the same name.
Contexts are stored locally in ~/.rocketvault/contexts.json; saving one does
not contact the server or verify that it exists.

--ca-cert and --insecure-skip-verify configure TLS trust for an actual
remote connection and are not part of the saved context.`,
		Example: `  # Save a context with a default username and vault
  rocketvault context add <name> \
    --server https://vault.example.com \
    --default-username <username> --default-vault <vault>

  # Save a context with just a server URL
  rocketvault context add <name> --server https://vault.example.com`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			server, _ := cmd.Flags().GetString("server")
			username, _ := cmd.Flags().GetString("default-username")
			vault, _ := cmd.Flags().GetString("default-vault")
			if server == "" {
				return fmt.Errorf("--server is required")
			}
			// Validate here rather than at request time: a context saved as
			// "vault.example.com" fails later with an opaque transport
			// error, which is confusing exactly when someone is first
			// configuring remote mode.
			parsed, err := url.Parse(server)
			if err != nil {
				return fmt.Errorf("--server %q is not a valid URL: %w", server, err)
			}
			if parsed.Scheme != "http" && parsed.Scheme != "https" {
				return fmt.Errorf(
					"--server %q needs an http:// or https:// scheme (got %q)", server, parsed.Scheme)
			}
			if parsed.Host == "" {
				return fmt.Errorf("--server %q has no host", server)
			}
			return common.AddContext(args[0], common.Context{Server: server, Username: username, Vault: vault})
		},
	}
	addCmd.Flags().String("default-username", "", "Default username for this context")
	addCmd.Flags().String("default-vault", "", "Default vault for this context")
	parent.AddCommand(addCmd)
	return parent
}
