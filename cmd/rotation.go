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
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"password-manager/common"
	"password-manager/internal/container"
	"password-manager/internal/domain"
	"password-manager/internal/logging"
	"password-manager/internal/repositories"
	"password-manager/internal/services/secrets"
)

var (
	policyName        string
	policyDescription string
	policyInterval    int
	policyReminder    int
	policyAutoRotate  bool
	policyID          string
	secretID          string
)

// rotationCmd represents the rotation command group
var rotationCmd = &cobra.Command{
	Use:   "rotation",
	Short: "Manage secret rotation policies",
	Long: `Manage secret rotation policies including creation, assignment,
monitoring, and automated rotation of secrets.`,
	Example: `  # Create a new rotation policy
  password-manager secrets rotation create --name "Monthly DB Password" --interval 30

  # List all rotation policies
  password-manager secrets rotation list

  # Assign a policy to a secret
  password-manager secrets rotation assign --policy-id <uuid> --secret-id <uuid>

  # Manually rotate a secret
  password-manager secrets rotation rotate --secret-id <uuid> --policy-id <uuid>`,
}

func init() {
	secretsCmd.AddCommand(rotationCmd)

	// Add subcommands
	rotationCmd.AddCommand(rotationCreateCmd)
	rotationCmd.AddCommand(rotationListCmd)
	rotationCmd.AddCommand(rotationUpdateCmd)
	rotationCmd.AddCommand(rotationDeleteCmd)
	rotationCmd.AddCommand(rotationAssignCmd)
	rotationCmd.AddCommand(rotationUnassignCmd)
	rotationCmd.AddCommand(rotationRotateCmd)
	rotationCmd.AddCommand(rotationHistoryCmd)
	rotationCmd.AddCommand(rotationStatusCmd)
}

// rotationCreateCmd represents the rotation create command
var rotationCreateCmd = &cobra.Command{
	Use:     "create",
	Short:   "Create a new rotation policy",
	Long:    `Create a new rotation policy with specified parameters.`,
	Example: `password-manager secrets rotation create --name "Monthly Rotation" --interval 30 --reminder 7 --auto-rotate`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationCreate(cmd)
	},
}

// rotationListCmd represents the rotation list command
var rotationListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all rotation policies",
	Long:    `List all rotation policies for the current user.`,
	Example: `password-manager secrets rotation list`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationList(cmd)
	},
}

// rotationUpdateCmd represents the rotation update command
var rotationUpdateCmd = &cobra.Command{
	Use:     "update",
	Short:   "Update a rotation policy",
	Long:    `Update an existing rotation policy.`,
	Example: `password-manager secrets rotation update --id <uuid> --name "New Name" --interval 60`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationUpdate(cmd)
	},
}

// rotationDeleteCmd represents the rotation delete command
var rotationDeleteCmd = &cobra.Command{
	Use:     "delete",
	Short:   "Delete a rotation policy",
	Long:    `Delete an existing rotation policy.`,
	Example: `password-manager secrets rotation delete --id <uuid>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationDelete(cmd)
	},
}

// rotationAssignCmd represents the rotation assign command
var rotationAssignCmd = &cobra.Command{
	Use:     "assign",
	Short:   "Assign a policy to a secret",
	Long:    `Assign a rotation policy to a secret.`,
	Example: `password-manager secrets rotation assign --policy-id <uuid> --secret-id <uuid>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationAssign(cmd)
	},
}

// rotationUnassignCmd represents the rotation unassign command
var rotationUnassignCmd = &cobra.Command{
	Use:     "unassign",
	Short:   "Remove a policy from a secret",
	Long:    `Remove a rotation policy from a secret.`,
	Example: `password-manager secrets rotation unassign --policy-id <uuid> --secret-id <uuid>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationUnassign(cmd)
	},
}

// rotationRotateCmd represents the rotation rotate command
var rotationRotateCmd = &cobra.Command{
	Use:     "rotate",
	Short:   "Manually rotate a secret",
	Long:    `Manually rotate a secret according to its assigned policy.`,
	Example: `password-manager secrets rotation rotate --secret-id <uuid> --policy-id <uuid>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationRotate(cmd)
	},
}

// rotationHistoryCmd represents the rotation history command
var rotationHistoryCmd = &cobra.Command{
	Use:     "history",
	Short:   "View rotation history for a secret",
	Long:    `View the rotation history for a specific secret.`,
	Example: `password-manager secrets rotation history --secret-id <uuid>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationHistory(cmd)
	},
}

// rotationStatusCmd represents the rotation status command
var rotationStatusCmd = &cobra.Command{
	Use:     "status",
	Short:   "View rotation status and due rotations",
	Long:    `View the current rotation status and secrets due for rotation.`,
	Example: `password-manager secrets rotation status`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationStatus(cmd)
	},
}

func init() {
	// Create command flags
	rotationCreateCmd.Flags().StringVar(&policyName, "name", "", "Policy name (required)")
	rotationCreateCmd.Flags().StringVar(&policyDescription, "description", "", "Policy description")
	rotationCreateCmd.Flags().IntVar(&policyInterval, "interval", 30, "Rotation interval in days")
	rotationCreateCmd.Flags().IntVar(&policyReminder, "reminder", 7, "Reminder days before rotation")
	rotationCreateCmd.Flags().BoolVar(&policyAutoRotate, "auto-rotate", false, "Enable automatic rotation")
	rotationCreateCmd.MarkFlagRequired("name")

	// Update command flags
	rotationUpdateCmd.Flags().StringVar(&policyID, "id", "", "Policy ID (required)")
	rotationUpdateCmd.Flags().StringVar(&policyName, "name", "", "Policy name")
	rotationUpdateCmd.Flags().StringVar(&policyDescription, "description", "", "Policy description")
	rotationUpdateCmd.Flags().IntVar(&policyInterval, "interval", 0, "Rotation interval in days")
	rotationUpdateCmd.Flags().IntVar(&policyReminder, "reminder", 0, "Reminder days before rotation")
	rotationUpdateCmd.Flags().BoolVar(&policyAutoRotate, "auto-rotate", false, "Enable automatic rotation")
	rotationUpdateCmd.MarkFlagRequired("id")

	// Delete command flags
	rotationDeleteCmd.Flags().StringVar(&policyID, "id", "", "Policy ID (required)")
	rotationDeleteCmd.MarkFlagRequired("id")

	// Assign command flags
	rotationAssignCmd.Flags().StringVar(&policyID, "policy-id", "", "Policy ID (required)")
	rotationAssignCmd.Flags().StringVar(&secretID, "secret-id", "", "Secret ID (required)")
	rotationAssignCmd.MarkFlagRequired("policy-id")
	rotationAssignCmd.MarkFlagRequired("secret-id")

	// Unassign command flags
	rotationUnassignCmd.Flags().StringVar(&policyID, "policy-id", "", "Policy ID (required)")
	rotationUnassignCmd.Flags().StringVar(&secretID, "secret-id", "", "Secret ID (required)")
	rotationUnassignCmd.MarkFlagRequired("policy-id")
	rotationUnassignCmd.MarkFlagRequired("secret-id")

	// Rotate command flags
	rotationRotateCmd.Flags().StringVar(&secretID, "secret-id", "", "Secret ID (required)")
	rotationRotateCmd.Flags().StringVar(&policyID, "policy-id", "", "Policy ID (required)")
	rotationRotateCmd.MarkFlagRequired("secret-id")
	rotationRotateCmd.MarkFlagRequired("policy-id")

	// History command flags
	rotationHistoryCmd.Flags().StringVar(&secretID, "secret-id", "", "Secret ID (required)")
	rotationHistoryCmd.MarkFlagRequired("secret-id")

	// Status command has no flags
}

func runRotationCreate(cmd *cobra.Command) error {
	ctx := cmd.Context()
	db := ctx.Value(common.DBKey).(*sql.DB)
	logger := ctx.Value(common.LogKey).(*logging.Logger)
	userID := ctx.Value(common.UserIDKey).(uuid.UUID)

	// Create repository
	repo := repositories.NewRotationPolicyRepository(db, logger)

	// Create policy
	policy := &domain.RotationPolicy{
		UserID:       userID,
		Name:         policyName,
		Description:  policyDescription,
		IntervalDays: policyInterval,
		Enabled:      true,
		ReminderDays: policyReminder,
		AutoRotate:   policyAutoRotate,
	}

	err := repo.Create(ctx, policy)
	if err != nil {
		return fmt.Errorf("failed to create rotation policy: %w", err)
	}

	fmt.Printf("✅ Rotation policy created successfully!\n")
	fmt.Printf("Policy ID: %s\n", policy.ID)
	fmt.Printf("Name: %s\n", policy.Name)
	fmt.Printf("Interval: %d days\n", policy.IntervalDays)
	fmt.Printf("Auto-rotate: %t\n", policy.AutoRotate)

	return nil
}

func runRotationList(cmd *cobra.Command) error {
	ctx := cmd.Context()
	db := ctx.Value(common.DBKey).(*sql.DB)
	logger := ctx.Value(common.LogKey).(*logging.Logger)
	userID := ctx.Value(common.UserIDKey).(uuid.UUID)

	// Create repository
	repo := repositories.NewRotationPolicyRepository(db, logger)

	// Get policies
	policies, err := repo.ListByUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to list rotation policies: %w", err)
	}

	if len(policies) == 0 {
		fmt.Println("No rotation policies found.")
		return nil
	}

	// Display results in a table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tINTERVAL\tAUTO-ROTATE\tENABLED\tCREATED")
	fmt.Fprintln(w, "--\t----\t--------\t-----------\t-------\t-------")

	for _, p := range policies {
		fmt.Fprintf(w, "%s\t%s\t%d days\t%t\t%t\t%s\n",
			p.ID.String()[:8]+"...",
			p.Name,
			p.IntervalDays,
			p.AutoRotate,
			p.Enabled,
			p.CreatedAt.Format("2006-01-02"))
	}

	w.Flush()
	fmt.Printf("\n📊 Found %d rotation policies\n", len(policies))

	return nil
}

func runRotationUpdate(cmd *cobra.Command) error {
	ctx := cmd.Context()
	db := ctx.Value(common.DBKey).(*sql.DB)
	logger := ctx.Value(common.LogKey).(*logging.Logger)
	userID := ctx.Value(common.UserIDKey).(uuid.UUID)

	// Parse policy ID
	pid, err := uuid.Parse(policyID)
	if err != nil {
		return fmt.Errorf("invalid policy ID: %w", err)
	}

	// Create repository
	repo := repositories.NewRotationPolicyRepository(db, logger)

	// Get existing policy
	policy, err := repo.Read(ctx, pid)
	if err != nil {
		return fmt.Errorf("failed to read policy: %w", err)
	}

	// Verify ownership
	if policy.UserID != userID {
		return fmt.Errorf("you don't own this policy")
	}

	// Update fields if provided
	if cmd.Flags().Changed("name") {
		policy.Name = policyName
	}
	if cmd.Flags().Changed("description") {
		policy.Description = policyDescription
	}
	if cmd.Flags().Changed("interval") {
		policy.IntervalDays = policyInterval
	}
	if cmd.Flags().Changed("reminder") {
		policy.ReminderDays = policyReminder
	}
	if cmd.Flags().Changed("auto-rotate") {
		policy.AutoRotate = policyAutoRotate
	}

	// Update policy
	err = repo.Update(ctx, policy)
	if err != nil {
		return fmt.Errorf("failed to update rotation policy: %w", err)
	}

	fmt.Printf("✅ Rotation policy updated successfully!\n")
	return nil
}

func runRotationDelete(cmd *cobra.Command) error {
	ctx := cmd.Context()
	db := ctx.Value(common.DBKey).(*sql.DB)
	logger := ctx.Value(common.LogKey).(*logging.Logger)
	userID := ctx.Value(common.UserIDKey).(uuid.UUID)

	// Parse policy ID
	pid, err := uuid.Parse(policyID)
	if err != nil {
		return fmt.Errorf("invalid policy ID: %w", err)
	}

	// Create repository
	repo := repositories.NewRotationPolicyRepository(db, logger)

	// Get existing policy
	policy, err := repo.Read(ctx, pid)
	if err != nil {
		return fmt.Errorf("failed to read policy: %w", err)
	}

	// Verify ownership
	if policy.UserID != userID {
		return fmt.Errorf("you don't own this policy")
	}

	// Delete policy
	err = repo.Delete(ctx, pid)
	if err != nil {
		return fmt.Errorf("failed to delete rotation policy: %w", err)
	}

	fmt.Printf("✅ Rotation policy deleted successfully!\n")
	return nil
}

func runRotationAssign(cmd *cobra.Command) error {
	ctx := cmd.Context()
	db := ctx.Value(common.DBKey).(*sql.DB)
	logger := ctx.Value(common.LogKey).(*logging.Logger)
	userID := ctx.Value(common.UserIDKey).(uuid.UUID)

	// Parse IDs
	pid, err := uuid.Parse(policyID)
	if err != nil {
		return fmt.Errorf("invalid policy ID: %w", err)
	}

	sid, err := uuid.Parse(secretID)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}

	// Create repository
	repo := repositories.NewRotationPolicyRepository(db, logger)

	// Verify policy ownership
	policy, err := repo.Read(ctx, pid)
	if err != nil {
		return fmt.Errorf("failed to read policy: %w", err)
	}
	if policy.UserID != userID {
		return fmt.Errorf("you don't own this policy")
	}

	// Verify secret ownership
	secretRepo := repositories.NewSecretRepository(db, logger)
	secret, err := secretRepo.Read(ctx, sid)
	if err != nil {
		return fmt.Errorf("failed to read secret: %w", err)
	}
	if secret.UserID != userID {
		return fmt.Errorf("you don't own this secret")
	}

	// Assign policy with proper timestamps
	assignedAt := time.Now()
	nextRotationAt := assignedAt.AddDate(0, 0, policy.IntervalDays)
	err = repo.AssignToSecret(ctx, sid, pid, assignedAt, nextRotationAt)
	if err != nil {
		return fmt.Errorf("failed to assign policy to secret: %w", err)
	}

	fmt.Printf("✅ Policy assigned to secret successfully!\n")
	return nil
}

func runRotationUnassign(cmd *cobra.Command) error {
	ctx := cmd.Context()
	db := ctx.Value(common.DBKey).(*sql.DB)
	logger := ctx.Value(common.LogKey).(*logging.Logger)
	userID := ctx.Value(common.UserIDKey).(uuid.UUID)

	// Parse IDs
	pid, err := uuid.Parse(policyID)
	if err != nil {
		return fmt.Errorf("invalid policy ID: %w", err)
	}

	sid, err := uuid.Parse(secretID)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}

	// Create repository
	repo := repositories.NewRotationPolicyRepository(db, logger)

	// Verify policy ownership
	policy, err := repo.Read(ctx, pid)
	if err != nil {
		return fmt.Errorf("failed to read policy: %w", err)
	}
	if policy.UserID != userID {
		return fmt.Errorf("you don't own this policy")
	}

	// Verify secret ownership
	secretRepo := repositories.NewSecretRepository(db, logger)
	secret, err := secretRepo.Read(ctx, sid)
	if err != nil {
		return fmt.Errorf("failed to read secret: %w", err)
	}
	if secret.UserID != userID {
		return fmt.Errorf("you don't own this secret")
	}

	// Unassign policy
	err = repo.RemoveFromSecret(ctx, sid, pid)
	if err != nil {
		return fmt.Errorf("failed to remove policy from secret: %w", err)
	}

	fmt.Printf("✅ Policy removed from secret successfully!\n")
	return nil
}

func runRotationRotate(cmd *cobra.Command) error {
	ctx := cmd.Context()
	db := ctx.Value(common.DBKey).(*sql.DB)
	logger := ctx.Value(common.LogKey).(*logging.Logger)
	userID := ctx.Value(common.UserIDKey).(uuid.UUID)

	// Parse IDs
	sid, err := uuid.Parse(secretID)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}

	pid, err := uuid.Parse(policyID)
	if err != nil {
		return fmt.Errorf("invalid policy ID: %w", err)
	}

	// Create service container for scheduler access
	serviceContainer, err := container.NewServiceContainer(container.Config{
		Database: db,
		Logger:   logger,
	})
	if err != nil {
		return fmt.Errorf("failed to create service container: %w", err)
	}
	defer serviceContainer.Close()

	// Get rotation service from container
	rotationService := serviceContainer.GetRotationService()

	// Perform manual rotation
	err = rotationService.PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: sid,
		PolicyID: pid,
		UserID:   userID,
	})
	if err != nil {
		return fmt.Errorf("failed to rotate secret: %w", err)
	}

	fmt.Printf("✅ Secret rotated successfully!\n")
	return nil
}

func runRotationHistory(cmd *cobra.Command) error {
	ctx := cmd.Context()
	db := ctx.Value(common.DBKey).(*sql.DB)
	logger := ctx.Value(common.LogKey).(*logging.Logger)
	userID := ctx.Value(common.UserIDKey).(uuid.UUID)

	// Parse secret ID
	sid, err := uuid.Parse(secretID)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}

	// Create repository
	repo := repositories.NewRotationPolicyRepository(db, logger)

	// Verify secret ownership
	secretRepo := repositories.NewSecretRepository(db, logger)
	secret, err := secretRepo.Read(ctx, sid)
	if err != nil {
		return fmt.Errorf("failed to read secret: %w", err)
	}
	if secret.UserID != userID {
		return fmt.Errorf("you don't own this secret")
	}

	// Get rotation history
	history, err := repo.GetRotationHistory(ctx, sid)
	if err != nil {
		return fmt.Errorf("failed to get rotation history: %w", err)
	}

	if len(history) == 0 {
		fmt.Printf("No rotation history found for secret %s\n", secretID)
		return nil
	}

	// Display results in a table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ROTATED_AT\tTRIGGERED_BY\tPREV_VERSION\tNEW_VERSION\tNOTES")
	fmt.Fprintln(w, "----------\t------------\t------------\t-----------\t-----")

	for _, h := range history {
		notes := h.Notes
		if len(notes) > 30 {
			notes = notes[:27] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\n",
			h.RotatedAt.Format("2006-01-02 15:04"),
			h.TriggeredBy,
			h.PreviousVersion,
			h.NewVersion,
			notes)
	}

	w.Flush()
	fmt.Printf("\n📊 Found %d rotation events\n", len(history))

	return nil
}

func runRotationStatus(cmd *cobra.Command) error {
	ctx := cmd.Context()
	db := ctx.Value(common.DBKey).(*sql.DB)
	logger := ctx.Value(common.LogKey).(*logging.Logger)
	userID := ctx.Value(common.UserIDKey).(uuid.UUID)

	// Create repository
	repo := repositories.NewRotationPolicyRepository(db, logger)

	// Get due rotations
	due, err := repo.GetDueRotations(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get due rotations: %w", err)
	}

	// Get upcoming reminders
	reminders, err := repo.GetUpcomingReminders(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get upcoming reminders: %w", err)
	}

	fmt.Printf("🔄 Rotation Status\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	if len(due) > 0 {
		fmt.Printf("⚠️  Secrets due for rotation:\n")
		for _, d := range due {
			nextRotation := "Unknown"
			if d.NextRotationAt != nil {
				nextRotation = d.NextRotationAt.Format("2006-01-02")
			}
			fmt.Printf("  • Secret %s (next: %s)\n", d.SecretID.String()[:8]+"...", nextRotation)
		}
		fmt.Println()
	} else {
		fmt.Printf("✅ No secrets are currently due for rotation\n\n")
	}

	if len(reminders) > 0 {
		fmt.Printf("🔔 Upcoming reminders:\n")
		for _, r := range reminders {
			fmt.Printf("  • Secret %s (%s reminder)\n", r.SecretID.String()[:8]+"...", r.ReminderType)
		}
		fmt.Println()
	} else {
		fmt.Printf("✅ No upcoming reminders\n\n")
	}

	// Get all policies and their assignments
	policies, err := repo.ListByUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to list policies: %w", err)
	}

	if len(policies) > 0 {
		fmt.Printf("📋 Active rotation policies:\n")
		for _, p := range policies {
			if p.Enabled {
				fmt.Printf("  • %s: every %d days", p.Name, p.IntervalDays)
				if p.AutoRotate {
					fmt.Printf(" (auto-rotate enabled)")
				}
				fmt.Println()
			}
		}
	}

	return nil
}
