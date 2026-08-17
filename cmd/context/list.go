package contextcli

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/formatter"
)

func InitContextList(parent *cobra.Command) *cobra.Command {
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List saved server contexts",
		RunE: func(cmd *cobra.Command, args []string) error {
			contexts, current, err := common.ListContexts()
			if err != nil {
				return err
			}

			fmtr, ok := cmd.Context().Value(common.OutputFormatterKey).(formatter.Formatter)
			if !ok {
				return fmt.Errorf("output formatter not available in context")
			}

			names := make([]string, 0, len(contexts))
			for name := range contexts {
				names = append(names, name)
			}
			sort.Strings(names)

			headers := []string{"Name", "Server", "Default Username", "Default Vault", "Current"}
			rows := make([][]string, 0, len(names))
			for _, name := range names {
				ctx := contexts[name]
				marker := ""
				if name == current {
					marker = "*"
				}
				rows = append(rows, []string{name, ctx.Server, ctx.Username, ctx.Vault, marker})
			}
			return fmtr.Write(cmd.OutOrStdout(), headers, rows)
		},
	}
	parent.AddCommand(listCmd)
	return parent
}
