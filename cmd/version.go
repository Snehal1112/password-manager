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
	"database/sql"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"password-manager/common"
	"password-manager/internal/domain"
	"password-manager/internal/logging"
	"password-manager/internal/repositories"
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
  password-manager version list --secret-id <uuid>

  # Get a specific version of a secret
  password-manager version get --secret-id <uuid> --version 2

  # Get the latest version of a secret
  password-manager version latest --secret-id <uuid>`,
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
	Example: `password-manager version list --secret-id 123e4567-e89b-12d3-a456-426614174000`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runVersionList(cmd)
	},
}

// versionGetCmd represents the version get command
var versionGetCmd = &cobra.Command{
	Use:     "get",
	Short:   "Get a specific version of a secret",
	Long:    `Retrieve a specific historical version of a secret.`,
	Example: `password-manager version get --secret-id 123e4567-e89b-12d3-a456-426614174000 --version 2`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runVersionGet(cmd)
	},
}

// versionLatestCmd represents the version latest command
var versionLatestCmd = &cobra.Command{
	Use:     "latest",
	Short:   "Get the latest version of a secret",
	Long:    `Retrieve the most recent version of a secret.`,
	Example: `password-manager version latest --secret-id 123e4567-e89b-12d3-a456-426614174000`,
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
	db := ctx.Value(common.DBKey).(*sql.DB)
	logger := ctx.Value(common.LogKey).(*logging.Logger)

	// Parse secret ID
	secretID, err := uuid.Parse(versionSecretID)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}

	// Create repository
	repo := repositories.NewSecretRepository(db, logger)

	// Get versions
	versions, err := repo.GetVersions(ctx, secretID)
	if err != nil {
		return fmt.Errorf("failed to get versions: %w", err)
	}

	if len(versions) == 0 {
		fmt.Printf("No versions found for secret %s\n", versionSecretID)
		return nil
	}

	// Display results in a table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "VERSION\tCREATED_AT\tNAME")
	fmt.Fprintln(w, "-------\t----------\t----")

	for _, v := range versions {
		fmt.Fprintf(w, "%d\t%s\t%s\n",
			v.Version,
			v.CreatedAt.Format("2006-01-02 15:04:05"),
			v.Name)
	}

	w.Flush()
	fmt.Printf("\n📊 Found %d versions for secret %s\n", len(versions), versionSecretID)

	return nil
}

func runVersionGet(cmd *cobra.Command) error {
	ctx := cmd.Context()
	db := ctx.Value(common.DBKey).(*sql.DB)
	logger := ctx.Value(common.LogKey).(*logging.Logger)

	// Parse secret ID
	secretID, err := uuid.Parse(versionSecretID)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}

	// Create repository
	repo := repositories.NewSecretRepository(db, logger)

	// Get specific version
	version, err := repo.GetVersion(ctx, secretID, versionNumber)
	if err != nil {
		return fmt.Errorf("failed to get version: %w", err)
	}

	// Display version details
	fmt.Printf("🔍 Secret Version Details\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Secret ID: %s\n", version.SecretID.String())
	fmt.Printf("Version:   %d\n", version.Version)
	fmt.Printf("Name:      %s\n", version.Name)
	fmt.Printf("Value:     %s\n", version.Value)
	fmt.Printf("Created:   %s\n", version.CreatedAt.Format("2006-01-02 15:04:05"))

	return nil
}

func runVersionLatest(cmd *cobra.Command) error {
	ctx := cmd.Context()
	db := ctx.Value(common.DBKey).(*sql.DB)
	logger := ctx.Value(common.LogKey).(*logging.Logger)

	// Parse secret ID
	secretID, err := uuid.Parse(versionSecretID)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}

	// Create repository
	repo := repositories.NewSecretRepository(db, logger)

	// Get current secret
	currentSecret, err := repo.Read(ctx, secretID)
	if err != nil {
		return fmt.Errorf("failed to get current secret: %w", err)
	}

	// Convert to SecretVersion for display
	version := &domain.SecretVersion{
		SecretID:  currentSecret.ID,
		UserID:    currentSecret.UserID,
		Name:      currentSecret.Name,
		Value:     currentSecret.Value,
		Version:   currentSecret.Version,
		CreatedAt: currentSecret.CreatedAt,
	}

	// Display version details
	fmt.Printf("🔍 Latest Secret Version Details\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Secret ID: %s\n", version.SecretID.String())
	fmt.Printf("User ID:   %s\n", version.UserID.String())
	fmt.Printf("Version:   %d\n", version.Version)
	fmt.Printf("Name:      %s\n", version.Name)
	fmt.Printf("Value:     %s\n", version.Value)
	fmt.Printf("Created:   %s\n", version.CreatedAt.Format("2006-01-02 15:04:05"))

	return nil
}
