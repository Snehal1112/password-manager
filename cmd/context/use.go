package contextcli

import (
	"github.com/spf13/cobra"

	"rocketvault/common"
)

func InitContextUse(parent *cobra.Command) *cobra.Command {
	useCmd := &cobra.Command{
		Use:   "use <name>",
		Short: "Set the current server context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return common.UseContext(args[0])
		},
	}
	parent.AddCommand(useCmd)
	return parent
}
