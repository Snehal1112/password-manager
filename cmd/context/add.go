package contextcli

import (
	"fmt"

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
		Use:     "add <name>",
		Short:   "Save a named remote server context",
		Example: `  rocketvault context add prod --server https://vault.prod.example.com --default-username admin`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			server, _ := cmd.Flags().GetString("server")
			username, _ := cmd.Flags().GetString("default-username")
			vault, _ := cmd.Flags().GetString("default-vault")
			if server == "" {
				return fmt.Errorf("--server is required")
			}
			return common.AddContext(args[0], common.Context{Server: server, Username: username, Vault: vault})
		},
	}
	addCmd.Flags().String("default-username", "", "Default username for this context")
	addCmd.Flags().String("default-vault", "", "Default vault for this context")
	parent.AddCommand(addCmd)
	return parent
}
