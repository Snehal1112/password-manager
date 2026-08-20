/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package cmd

import (
	"fmt"
	"text/tabwriter"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/model"
)

var (
	versionSecretID string
	versionNumber   int
)

// versionCmd represents the version command group
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Manage secret versions",
	Long: `View, retrieve, and manage historical versions of secrets.
Supports listing versions, retrieving specific versions, and version history.`,
	Example: `  # List all versions of a secret
  rocketvault secrets version list --secret-id <uuid> --username admin --password admin123 --totp-code <code>

  # Get a specific version of a secret
  rocketvault secrets version get --secret-id <uuid> --version 2 --username admin --password admin123 --totp-code <code>

  # Get the latest version of a secret
  rocketvault secrets version latest --secret-id <uuid> --username admin --password admin123 --totp-code <code>`,
}

func init() {
	secretsCmd.AddCommand(versionCmd)

	// Add subcommands
	versionCmd.AddCommand(versionListCmd)
	versionCmd.AddCommand(versionGetCmd)
	versionCmd.AddCommand(versionLatestCmd)
}

// versionListCmd represents the version list command
var versionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all versions of a secret",
	Long:  `List all historical versions of a secret with their metadata.`,
	Example: `  # List all versions of a secret
  rocketvault secrets version list --secret-id 123e4567-e89b-12d3-a456-426614174000 --username admin --password admin123 --totp-code <code>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runVersionList(cmd)
	},
}

// versionGetCmd represents the version get command
var versionGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a specific version of a secret",
	Long:  `Retrieve a specific historical version of a secret.`,
	Example: `  # Get version 2 of a secret
  rocketvault secrets version get --secret-id 123e4567-e89b-12d3-a456-426614174000 --version 2 --username admin --password admin123 --totp-code <code>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runVersionGet(cmd)
	},
}

// versionLatestCmd represents the version latest command
var versionLatestCmd = &cobra.Command{
	Use:   "latest",
	Short: "Get the latest version of a secret",
	Long:  `Retrieve the most recent version of a secret.`,
	Example: `  # Get the latest version of a secret
  rocketvault secrets version latest --secret-id 123e4567-e89b-12d3-a456-426614174000 --username admin --password admin123 --totp-code <code>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runVersionLatest(cmd)
	},
}

func init() {
	// List command flags
	versionListCmd.Flags().StringVar(&versionSecretID, "secret-id", "", "Secret ID to list versions for (required)")
	versionListCmd.MarkFlagRequired("secret-id") //nolint:errcheck,gosec

	// Get command flags
	versionGetCmd.Flags().StringVar(&versionSecretID, "secret-id", "", "Secret ID to get version for (required)")
	versionGetCmd.Flags().IntVar(&versionNumber, "version", 0, "Version number to retrieve (required)")
	versionGetCmd.MarkFlagRequired("secret-id") //nolint:errcheck,gosec
	versionGetCmd.MarkFlagRequired("version")   //nolint:errcheck,gosec

	// Latest command flags
	versionLatestCmd.Flags().StringVar(&versionSecretID, "secret-id", "", "Secret ID to get latest version for (required)")
	versionLatestCmd.MarkFlagRequired("secret-id") //nolint:errcheck,gosec

	// Every subcommand resolves a vault, so each needs the selection flag.
	for _, c := range []*cobra.Command{versionListCmd, versionGetCmd, versionLatestCmd} {
		c.Flags().String("vault", "", "vault name (default: ROCKETVAULT_VAULT env, config, or \"default\")")
	}
}

func runVersionList(cmd *cobra.Command) error {
	ctx := cmd.Context()
	userID, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
	if !ok {
		return fmt.Errorf("user ID not available in context")
	}

	secretID, err := uuid.Parse(versionSecretID)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}

	sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
	if !ok || sc == nil {
		return fmt.Errorf("service container not available in context")
	}

	// The CLI bypasses PolicyMiddleware entirely, so this is the only
	// authorization enforcement point on this path. Listing versions is a
	// metadata read, matching the HTTP route's ActionSecretsReadMetadata.
	vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, userID, model.ActionSecretsReadMetadata, model.OpList)
	if err != nil {
		return err
	}

	// A vault scope, not an owner scope: an owner scope survives revocation,
	// so a user who created a secret could still read its history after
	// losing access to the vault holding it.
	versions, err := sc.GetSecretService().GetSecretVersionsMetadata(ctx, secretID, model.NewVaultScope(vaultID, userID))
	if err != nil {
		return fmt.Errorf("failed to get versions: %w", err)
	}

	if len(versions) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "No versions found for secret %s\n", versionSecretID) //nolint:errcheck
		return nil
	}

	// No VALUE column: this command is authorized for metadata only. Use
	// "secrets version get --version N" to read one version's value, which
	// requires ActionSecretsGet.
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "VERSION\tCREATED_AT\tNAME") //nolint:errcheck
	fmt.Fprintln(w, "-------\t----------\t----") //nolint:errcheck
	for _, v := range versions {
		fmt.Fprintf(w, "%d\t%s\t%s\n", //nolint:errcheck
			v.Version, v.CreatedAt.Format("2006-01-02 15:04:05"), v.Name)
	}
	w.Flush()                                                                                             //nolint:errcheck,gosec
	fmt.Fprintf(cmd.OutOrStdout(), "\nFound %d versions for secret %s\n", len(versions), versionSecretID) //nolint:errcheck
	return nil
}

func runVersionGet(cmd *cobra.Command) error {
	ctx := cmd.Context()
	userID, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
	if !ok {
		return fmt.Errorf("user ID not available in context")
	}

	secretID, err := uuid.Parse(versionSecretID)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}

	sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
	if !ok || sc == nil {
		return fmt.Errorf("service container not available in context")
	}

	// Returns a plaintext value, so it requires ActionSecretsGet -- the same
	// action GET /secrets/{id}/versions/{n} requires.
	vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, userID, model.ActionSecretsGet, model.OpGet)
	if err != nil {
		return err
	}

	version, err := sc.GetSecretService().GetSecretVersion(ctx, secretID, versionNumber, model.NewVaultScope(vaultID, userID))
	if err != nil {
		return fmt.Errorf("failed to get version: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Secret ID: %s\nVersion:   %d\nName:      %s\nValue:     %s\nCreated:   %s\n", //nolint:errcheck
		version.SecretID, version.Version, version.Name, version.Value,
		version.CreatedAt.Format("2006-01-02 15:04:05"))
	return nil
}

func runVersionLatest(cmd *cobra.Command) error {
	ctx := cmd.Context()
	userID, ok := ctx.Value(common.UserIDKey).(uuid.UUID)
	if !ok {
		return fmt.Errorf("user ID not available in context")
	}

	secretID, err := uuid.Parse(versionSecretID)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}

	sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
	if !ok || sc == nil {
		return fmt.Errorf("service container not available in context")
	}

	// Returns a plaintext value, so it requires ActionSecretsGet.
	vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, userID, model.ActionSecretsGet, model.OpGet)
	if err != nil {
		return err
	}

	version, err := sc.GetSecretService().GetLatestSecretVersion(ctx, secretID, model.NewVaultScope(vaultID, userID))
	if err != nil {
		return fmt.Errorf("failed to get latest version: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Secret ID: %s\nVersion:   %d\nName:      %s\nValue:     %s\nCreated:   %s\n", //nolint:errcheck
		version.SecretID, version.Version, version.Name, version.Value,
		version.CreatedAt.Format("2006-01-02 15:04:05"))
	return nil
}
