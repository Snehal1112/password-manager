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
