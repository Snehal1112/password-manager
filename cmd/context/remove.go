package contextcli

import (
	"github.com/spf13/cobra"

	"rocketvault/common"
)

func InitContextRemove(parent *cobra.Command) *cobra.Command {
	removeCmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Delete a saved server context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return common.RemoveContext(args[0])
		},
	}
	parent.AddCommand(removeCmd)
	return parent
}
