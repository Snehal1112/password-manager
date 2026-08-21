package contextcli

import (
	"github.com/spf13/cobra"

	"rocketvault/common"
)

func InitContextUse(parent *cobra.Command) *cobra.Command {
	useCmd := &cobra.Command{
		Use:   "use <name>",
		Short: "Set the current server context",
		Long: `Mark a saved context as current, so 'rocketvault context current' and
'rocketvault context list' report it as active. Fails if the name was not
previously saved with 'rocketvault context add'. As of this release, no
other command yet acts on the current context: remote mode is rejected
outside the context group ("remote mode ... is not yet supported").`,
		Example: `  # Switch to a saved context
  rocketvault context use <name>`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return common.UseContext(args[0])
		},
	}
	parent.AddCommand(useCmd)
	return parent
}
