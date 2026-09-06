package contextcli

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/formatter"
)

func InitContextList(parent *cobra.Command) {
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List saved server contexts",
		Long: `List every saved context in a table: name, server, default username,
default vault, and whether it is the current context (set with 'rocketvault
context use'). Reads only the local context store; it does not contact any
server.`,
		Example: `  # List all saved contexts
  rocketvault context list

  # List all saved contexts as JSON
  rocketvault context list --output json`,
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
}
