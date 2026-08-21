package contextcli

import (
	"fmt"

	"github.com/spf13/cobra"

	"rocketvault/common"
)

func InitContextCurrent(parent *cobra.Command) *cobra.Command {
	currentCmd := &cobra.Command{
		Use:   "current",
		Short: "Show the current server context",
		Long: `Print the name and server URL of the context set by 'rocketvault context
use', or report that none is set (local mode). Reads only the local context
store; it does not contact the server.`,
		Example: `  # Show the current context
  rocketvault context current`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, name, err := common.CurrentContext()
			if err != nil {
				return err
			}
			if ctx == nil {
				_, err := fmt.Fprintln(cmd.OutOrStdout(), "no current context set (local mode)")
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s -> %s\n", name, ctx.Server)
			return err
		},
	}
	parent.AddCommand(currentCmd)
	return parent
}
