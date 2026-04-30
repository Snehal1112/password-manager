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

	"rocketvault/common"
	"rocketvault/internal/container"
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
  rocketvault version list --secret-id <uuid>

  # Get a specific version of a secret
  rocketvault version get --secret-id <uuid> --version 2

  # Get the latest version of a secret
  rocketvault version latest --secret-id <uuid>`,
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
	Use:     "list",
	Short:   "List all versions of a secret",
	Long:    `List all historical versions of a secret with their metadata.`,
	Example: `rocketvault version list --secret-id 123e4567-e89b-12d3-a456-426614174000`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runVersionList(cmd)
	},
}

// versionGetCmd represents the version get command
var versionGetCmd = &cobra.Command{
	Use:     "get",
	Short:   "Get a specific version of a secret",
	Long:    `Retrieve a specific historical version of a secret.`,
	Example: `rocketvault version get --secret-id 123e4567-e89b-12d3-a456-426614174000 --version 2`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runVersionGet(cmd)
	},
}

// versionLatestCmd represents the version latest command
var versionLatestCmd = &cobra.Command{
	Use:     "latest",
	Short:   "Get the latest version of a secret",
	Long:    `Retrieve the most recent version of a secret.`,
	Example: `rocketvault version latest --secret-id 123e4567-e89b-12d3-a456-426614174000`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runVersionLatest(cmd)
	},
}

func init() {
	// List command flags
	versionListCmd.Flags().StringVar(&versionSecretID, "secret-id", "", "Secret ID to list versions for (required)")
	versionListCmd.MarkFlagRequired("secret-id")

	// Get command flags
	versionGetCmd.Flags().StringVar(&versionSecretID, "secret-id", "", "Secret ID to get version for (required)")
	versionGetCmd.Flags().IntVar(&versionNumber, "version", 0, "Version number to retrieve (required)")
	versionGetCmd.MarkFlagRequired("secret-id")
	versionGetCmd.MarkFlagRequired("version")

	// Latest command flags
	versionLatestCmd.Flags().StringVar(&versionSecretID, "secret-id", "", "Secret ID to get latest version for (required)")
	versionLatestCmd.MarkFlagRequired("secret-id")
}

func runVersionList(cmd *cobra.Command) error {
	ctx := cmd.Context()
	userID := ctx.Value(common.UserIDKey).(uuid.UUID)

	secretID, err := uuid.Parse(versionSecretID)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}

	sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
	if !ok || sc == nil {
		return fmt.Errorf("service container not available in context")
	}

	versions, err := sc.GetSecretService().GetSecretVersions(ctx, secretID, userID)
	if err != nil {
		return fmt.Errorf("failed to get versions: %w", err)
	}

	if len(versions) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "No versions found for secret %s\n", versionSecretID)
		return nil
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "VERSION\tCREATED_AT\tNAME\tVALUE")
	fmt.Fprintln(w, "-------\t----------\t----\t-----")
	for _, v := range versions {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n",
			v.Version, v.CreatedAt.Format("2006-01-02 15:04:05"), v.Name, v.Value)
	}
	w.Flush()
	fmt.Fprintf(cmd.OutOrStdout(), "\nFound %d versions for secret %s\n", len(versions), versionSecretID)
	return nil
}

func runVersionGet(cmd *cobra.Command) error {
	ctx := cmd.Context()
	userID := ctx.Value(common.UserIDKey).(uuid.UUID)

	secretID, err := uuid.Parse(versionSecretID)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}

	sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
	if !ok || sc == nil {
		return fmt.Errorf("service container not available in context")
	}

	version, err := sc.GetSecretService().GetSecretVersion(ctx, secretID, versionNumber, userID)
	if err != nil {
		return fmt.Errorf("failed to get version: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Secret ID: %s\nVersion:   %d\nName:      %s\nValue:     %s\nCreated:   %s\n",
		version.SecretID, version.Version, version.Name, version.Value,
		version.CreatedAt.Format("2006-01-02 15:04:05"))
	return nil
}

func runVersionLatest(cmd *cobra.Command) error {
	ctx := cmd.Context()
	userID := ctx.Value(common.UserIDKey).(uuid.UUID)

	secretID, err := uuid.Parse(versionSecretID)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}

	sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
	if !ok || sc == nil {
		return fmt.Errorf("service container not available in context")
	}

	version, err := sc.GetSecretService().GetLatestSecretVersion(ctx, secretID, userID)
	if err != nil {
		return fmt.Errorf("failed to get latest version: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Secret ID: %s\nVersion:   %d\nName:      %s\nValue:     %s\nCreated:   %s\n",
		version.SecretID, version.Version, version.Name, version.Value,
		version.CreatedAt.Format("2006-01-02 15:04:05"))
	return nil
}
