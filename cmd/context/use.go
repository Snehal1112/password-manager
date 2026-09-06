package contextcli

import (
	"github.com/spf13/cobra"

	"rocketvault/common"
)

func InitContextUse(parent *cobra.Command) {
	useCmd := &cobra.Command{
		Use:   "use <name>",
		Short: "Set the current server context",
		Long: `Mark a saved context as current, so later commands target its server.

Commands with a remote adapter act on it directly. Every other command
refuses to run while a context is current, rather than silently operating
on the local instance -- run 'context unset' to return to local mode.`,
		Example: `  # Switch to a saved context
  rocketvault context use <name>`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return common.UseContext(args[0])
		},
	}
	parent.AddCommand(useCmd)
}
