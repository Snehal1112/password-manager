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
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, name, err := common.CurrentContext()
			if err != nil {
				return err
			}
			if ctx == nil {
				fmt.Fprintln(cmd.OutOrStdout(), "no current context set (local mode)")
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s -> %s\n", name, ctx.Server)
			return nil
		},
	}
	parent.AddCommand(currentCmd)
	return parent
}
