package contextcli

import (
	"github.com/spf13/cobra"

	"rocketvault/common"
)

func InitContextUnset(parent *cobra.Command) {
	unsetCmd := &cobra.Command{
		Use:   "unset",
		Short: "Clear the current server context, returning to local mode",
		Long: `Clear the current context, so subsequent commands run in local mode
against .rocketvault.yaml again. Unlike 'rocketvault context remove', the
saved context itself is left untouched -- 'rocketvault context use <name>'
switches back to it later. A no-op, not an error, if no context is
currently set.`,
		Example: `  # Stop targeting a remote server without deleting the saved context
  rocketvault context unset`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return common.UnsetCurrentContext()
		},
	}
	parent.AddCommand(unsetCmd)
}
