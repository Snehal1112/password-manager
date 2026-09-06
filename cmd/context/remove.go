package contextcli

import (
	"github.com/spf13/cobra"

	"rocketvault/common"
)

func InitContextRemove(parent *cobra.Command) {
	removeCmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Delete a saved server context",
		Long: `Delete a saved context by name. If it was the current context, the
current pointer is cleared too, so subsequent commands run in local mode
until another context is selected with 'rocketvault context use'. Removing
a name that does not exist is not an error.`,
		Example: `  # Remove a saved context
  rocketvault context remove <name>`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return common.RemoveContext(args[0])
		},
	}
	parent.AddCommand(removeCmd)
}
