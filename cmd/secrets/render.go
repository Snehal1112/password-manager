package secrets

import (
	"context"

	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
)

// renderSecret and renderSecrets are the one place cmd/secrets reaches for the
// output formatter. Local and remote paths both go through them, so the "is
// there a formatter in this context?" check exists once instead of six times.
func renderSecret[T any](cmd *cobra.Command, ctx context.Context, cols []vaultcli.Column[T], item T) error {
	return renderSecrets(cmd, ctx, cols, item)
}

func renderSecrets[T any](cmd *cobra.Command, ctx context.Context, cols []vaultcli.Column[T], items ...T) error {
	fmtr, err := vaultcli.CtxFormatter.From(ctx)
	if err != nil {
		return err
	}
	return vaultcli.Render(cmd.OutOrStdout(), fmtr, cols, items...)
}
