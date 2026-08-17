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
	secrets "rocketvault/internal/services/secrets"
	"rocketvault/model"
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
  rocketvault secrets rotation create --name "Monthly DB Password" --interval 30

  # List all rotation policies
  rocketvault secrets rotation list

  # Assign a policy to a secret
  rocketvault secrets rotation assign --policy-id <uuid> --secret-id <uuid>

  # Manually rotate a secret
  rocketvault secrets rotation rotate --secret-id <uuid> --policy-id <uuid>`,
}

func init() {
	secretsCmd.AddCommand(rotationCmd)

	// --vault is registered once, persistently, on the rotation command
	// group so every subcommand inherits it without re-registering it
	// individually.
	rotationCmd.PersistentFlags().String("vault", "", "Target vault name (default: \"default\")")

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
	Example: `rocketvault secrets rotation create --name "Monthly Rotation" --interval 30 --reminder 7 --auto-rotate`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationCreate(cmd)
	},
}

// rotationListCmd represents the rotation list command
var rotationListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all rotation policies",
	Long:    `List all rotation policies for the current user.`,
	Example: `rocketvault secrets rotation list`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationList(cmd)
	},
}

// rotationUpdateCmd represents the rotation update command
var rotationUpdateCmd = &cobra.Command{
	Use:     "update",
	Short:   "Update a rotation policy",
	Long:    `Update an existing rotation policy.`,
	Example: `rocketvault secrets rotation update --id <uuid> --name "New Name" --interval 60`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationUpdate(cmd)
	},
}

// rotationDeleteCmd represents the rotation delete command
var rotationDeleteCmd = &cobra.Command{
	Use:     "delete",
	Short:   "Delete a rotation policy",
	Long:    `Delete an existing rotation policy.`,
	Example: `rocketvault secrets rotation delete --id <uuid>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationDelete(cmd)
	},
}

// rotationAssignCmd represents the rotation assign command
var rotationAssignCmd = &cobra.Command{
	Use:     "assign",
	Short:   "Assign a policy to a secret",
	Long:    `Assign a rotation policy to a secret.`,
	Example: `rocketvault secrets rotation assign --policy-id <uuid> --secret-id <uuid>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationAssign(cmd)
	},
}

// rotationUnassignCmd represents the rotation unassign command
var rotationUnassignCmd = &cobra.Command{
	Use:     "unassign",
	Short:   "Remove a policy from a secret",
	Long:    `Remove a rotation policy from a secret.`,
	Example: `rocketvault secrets rotation unassign --policy-id <uuid> --secret-id <uuid>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationUnassign(cmd)
	},
}

// rotationRotateCmd represents the rotation rotate command
var rotationRotateCmd = &cobra.Command{
	Use:     "rotate",
	Short:   "Manually rotate a secret",
	Long:    `Manually rotate a secret according to its assigned policy.`,
	Example: `rocketvault secrets rotation rotate --secret-id <uuid> --policy-id <uuid>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationRotate(cmd)
	},
}

// rotationHistoryCmd represents the rotation history command
var rotationHistoryCmd = &cobra.Command{
	Use:     "history",
	Short:   "View rotation history for a secret",
	Long:    `View the rotation history for a specific secret.`,
	Example: `rocketvault secrets rotation history --secret-id <uuid>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationHistory(cmd)
	},
}

// rotationStatusCmd represents the rotation status command
var rotationStatusCmd = &cobra.Command{
	Use:     "status",
	Short:   "View rotation status and due rotations",
	Long:    `View the current rotation status and secrets due for rotation.`,
	Example: `rocketvault secrets rotation status`,
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
	rotationCreateCmd.MarkFlagRequired("name") //nolint:errcheck,gosec

	// Update command flags
	rotationUpdateCmd.Flags().StringVar(&policyID, "id", "", "Policy ID (required)")
	rotationUpdateCmd.Flags().StringVar(&policyName, "name", "", "Policy name")
	rotationUpdateCmd.Flags().StringVar(&policyDescription, "description", "", "Policy description")
	rotationUpdateCmd.Flags().IntVar(&policyInterval, "interval", 0, "Rotation interval in days")
	rotationUpdateCmd.Flags().IntVar(&policyReminder, "reminder", 0, "Reminder days before rotation")
	rotationUpdateCmd.Flags().BoolVar(&policyAutoRotate, "auto-rotate", false, "Enable automatic rotation")
	rotationUpdateCmd.MarkFlagRequired("id") //nolint:errcheck,gosec

	// Delete command flags
	rotationDeleteCmd.Flags().StringVar(&policyID, "id", "", "Policy ID (required)")
	rotationDeleteCmd.MarkFlagRequired("id") //nolint:errcheck,gosec

	// Assign command flags
	rotationAssignCmd.Flags().StringVar(&policyID, "policy-id", "", "Policy ID (required)")
	rotationAssignCmd.Flags().StringVar(&secretID, "secret-id", "", "Secret ID (required)")
	rotationAssignCmd.MarkFlagRequired("policy-id") //nolint:errcheck,gosec
	rotationAssignCmd.MarkFlagRequired("secret-id") //nolint:errcheck,gosec

	// Unassign command flags
	rotationUnassignCmd.Flags().StringVar(&policyID, "policy-id", "", "Policy ID (required)")
	rotationUnassignCmd.Flags().StringVar(&secretID, "secret-id", "", "Secret ID (required)")
	rotationUnassignCmd.MarkFlagRequired("policy-id") //nolint:errcheck,gosec
	rotationUnassignCmd.MarkFlagRequired("secret-id") //nolint:errcheck,gosec

	// Rotate command flags
	rotationRotateCmd.Flags().StringVar(&secretID, "secret-id", "", "Secret ID (required)")
	rotationRotateCmd.Flags().StringVar(&policyID, "policy-id", "", "Policy ID (required)")
	rotationRotateCmd.MarkFlagRequired("secret-id") //nolint:errcheck,gosec
	rotationRotateCmd.MarkFlagRequired("policy-id") //nolint:errcheck,gosec

	// History command flags
	rotationHistoryCmd.Flags().StringVar(&secretID, "secret-id", "", "Secret ID (required)")
	rotationHistoryCmd.MarkFlagRequired("secret-id") //nolint:errcheck,gosec

	// Status command has no flags
}

func runRotationCreate(cmd *cobra.Command) error {
	ctx := cmd.Context()
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok {
		return fmt.Errorf("unauthorized: missing authentication claims")
	}
	sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
	if !ok || sc == nil {
		return fmt.Errorf("service container not available in context")
	}
	vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, claims.UserID, model.ActionSecretsSet, model.OpCreate)
	if err != nil {
		return fmt.Errorf("vault authorization failed: %w", err)
	}
	scope := model.NewVaultScope(vaultID, claims.UserID)
	policy, err := sc.GetRotationService().CreatePolicy(ctx, secrets.CreatePolicyRequest{
		Scope:        scope,
		Name:         policyName,
		Description:  policyDescription,
		IntervalDays: policyInterval,
		Enabled:      true,
		ReminderDays: policyReminder,
		AutoRotate:   policyAutoRotate,
	})
	if err != nil {
		return fmt.Errorf("failed to create rotation policy: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Rotation policy created successfully\nPolicy ID: %s\nName: %s\nInterval: %d days\nAuto-rotate: %t\n", //nolint:errcheck
		policy.ID, policy.Name, policy.IntervalDays, policy.AutoRotate)
	return nil
}

func runRotationList(cmd *cobra.Command) error {
	ctx := cmd.Context()
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok {
		return fmt.Errorf("unauthorized: missing authentication claims")
	}
	sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
	if !ok || sc == nil {
		return fmt.Errorf("service container not available in context")
	}
	vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, claims.UserID, model.ActionSecretsReadMetadata, model.OpGet)
	if err != nil {
		return fmt.Errorf("vault authorization failed: %w", err)
	}
	scope := model.NewVaultScope(vaultID, claims.UserID)
	policies, err := sc.GetRotationService().ListPolicies(ctx, scope)
	if err != nil {
		return fmt.Errorf("failed to list rotation policies: %w", err)
	}
	if len(policies) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No rotation policies found.") //nolint:errcheck
		return nil
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tINTERVAL\tAUTO-ROTATE\tENABLED\tCREATED") //nolint:errcheck
	fmt.Fprintln(w, "--\t----\t--------\t-----------\t-------\t-------") //nolint:errcheck
	for _, p := range policies {
		fmt.Fprintf(w, "%s\t%s\t%d days\t%t\t%t\t%s\n", //nolint:errcheck
			p.ID.String()[:8]+"...", p.Name, p.IntervalDays,
			p.AutoRotate, p.Enabled, p.CreatedAt.Format("2006-01-02"))
	}
	w.Flush()                                                                       //nolint:errcheck,gosec
	fmt.Fprintf(cmd.OutOrStdout(), "\nFound %d rotation policies\n", len(policies)) //nolint:errcheck
	return nil
}

func runRotationUpdate(cmd *cobra.Command) error {
	ctx := cmd.Context()
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok {
		return fmt.Errorf("unauthorized: missing authentication claims")
	}
	sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
	if !ok || sc == nil {
		return fmt.Errorf("service container not available in context")
	}
	vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, claims.UserID, model.ActionSecretsSet, model.OpSet)
	if err != nil {
		return fmt.Errorf("vault authorization failed: %w", err)
	}
	scope := model.NewVaultScope(vaultID, claims.UserID)
	pid, err := uuid.Parse(policyID)
	if err != nil {
		return fmt.Errorf("invalid policy ID: %w", err)
	}
	existing, err := sc.GetRotationService().GetPolicy(ctx, pid, scope)
	if err != nil {
		return fmt.Errorf("failed to read policy: %w", err)
	}
	req := secrets.UpdatePolicyRequest{
		ID:           pid,
		Scope:        scope,
		Name:         existing.Name,
		Description:  existing.Description,
		IntervalDays: existing.IntervalDays,
		Enabled:      existing.Enabled,
		ReminderDays: existing.ReminderDays,
		AutoRotate:   existing.AutoRotate,
	}
	if cmd.Flags().Changed("name") {
		req.Name = policyName
	}
	if cmd.Flags().Changed("description") {
		req.Description = policyDescription
	}
	if cmd.Flags().Changed("interval") {
		req.IntervalDays = policyInterval
	}
	if cmd.Flags().Changed("reminder") {
		req.ReminderDays = policyReminder
	}
	if cmd.Flags().Changed("auto-rotate") {
		req.AutoRotate = policyAutoRotate
	}
	if _, err := sc.GetRotationService().UpdatePolicy(ctx, req); err != nil {
		return fmt.Errorf("failed to update rotation policy: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Rotation policy updated successfully.") //nolint:errcheck
	return nil
}

func runRotationDelete(cmd *cobra.Command) error {
	ctx := cmd.Context()
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok {
		return fmt.Errorf("unauthorized: missing authentication claims")
	}
	sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
	if !ok || sc == nil {
		return fmt.Errorf("service container not available in context")
	}
	vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, claims.UserID, model.ActionSecretsSet, model.OpDelete)
	if err != nil {
		return fmt.Errorf("vault authorization failed: %w", err)
	}
	scope := model.NewVaultScope(vaultID, claims.UserID)
	pid, err := uuid.Parse(policyID)
	if err != nil {
		return fmt.Errorf("invalid policy ID: %w", err)
	}
	if err := sc.GetRotationService().DeletePolicy(ctx, pid, scope); err != nil {
		return fmt.Errorf("failed to delete rotation policy: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Rotation policy deleted successfully.") //nolint:errcheck
	return nil
}

func runRotationAssign(cmd *cobra.Command) error {
	ctx := cmd.Context()
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok {
		return fmt.Errorf("unauthorized: missing authentication claims")
	}
	sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
	if !ok || sc == nil {
		return fmt.Errorf("service container not available in context")
	}
	vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, claims.UserID, model.ActionSecretsSet, model.OpSet)
	if err != nil {
		return fmt.Errorf("vault authorization failed: %w", err)
	}
	scope := model.NewVaultScope(vaultID, claims.UserID)
	pid, err := uuid.Parse(policyID)
	if err != nil {
		return fmt.Errorf("invalid policy ID: %w", err)
	}
	sid, err := uuid.Parse(secretID)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}
	if err := sc.GetRotationService().AssignPolicyToSecret(ctx, secrets.AssignPolicyRequest{
		SecretID: sid,
		PolicyID: pid,
		Scope:    scope,
	}); err != nil {
		return fmt.Errorf("failed to assign policy to secret: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Policy assigned to secret successfully.") //nolint:errcheck
	return nil
}

func runRotationUnassign(cmd *cobra.Command) error {
	ctx := cmd.Context()
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok {
		return fmt.Errorf("unauthorized: missing authentication claims")
	}
	sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
	if !ok || sc == nil {
		return fmt.Errorf("service container not available in context")
	}
	vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, claims.UserID, model.ActionSecretsSet, model.OpSet)
	if err != nil {
		return fmt.Errorf("vault authorization failed: %w", err)
	}
	scope := model.NewVaultScope(vaultID, claims.UserID)
	pid, err := uuid.Parse(policyID)
	if err != nil {
		return fmt.Errorf("invalid policy ID: %w", err)
	}
	sid, err := uuid.Parse(secretID)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}
	if err := sc.GetRotationService().RemovePolicyFromSecret(ctx, sid, pid, scope); err != nil {
		return fmt.Errorf("failed to remove policy from secret: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Policy removed from secret successfully.") //nolint:errcheck
	return nil
}

func runRotationRotate(cmd *cobra.Command) error {
	ctx := cmd.Context()
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok {
		return fmt.Errorf("unauthorized: missing authentication claims")
	}
	sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
	if !ok || sc == nil {
		return fmt.Errorf("service container not available in context")
	}
	vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, claims.UserID, model.ActionSecretsSet, model.OpRotate)
	if err != nil {
		return fmt.Errorf("vault authorization failed: %w", err)
	}
	scope := model.NewVaultScope(vaultID, claims.UserID)
	sid, err := uuid.Parse(secretID)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}
	pid, err := uuid.Parse(policyID)
	if err != nil {
		return fmt.Errorf("invalid policy ID: %w", err)
	}
	if err := sc.GetRotationService().PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: sid,
		PolicyID: pid,
		Scope:    scope,
	}); err != nil {
		return fmt.Errorf("failed to rotate secret: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Secret rotated successfully.") //nolint:errcheck
	return nil
}

func runRotationHistory(cmd *cobra.Command) error {
	ctx := cmd.Context()
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok {
		return fmt.Errorf("unauthorized: missing authentication claims")
	}
	sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
	if !ok || sc == nil {
		return fmt.Errorf("service container not available in context")
	}
	vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, claims.UserID, model.ActionSecretsReadMetadata, model.OpGet)
	if err != nil {
		return fmt.Errorf("vault authorization failed: %w", err)
	}
	scope := model.NewVaultScope(vaultID, claims.UserID)
	sid, err := uuid.Parse(secretID)
	if err != nil {
		return fmt.Errorf("invalid secret ID: %w", err)
	}
	history, err := sc.GetRotationService().GetRotationHistory(ctx, sid, scope)
	if err != nil {
		return fmt.Errorf("failed to get rotation history: %w", err)
	}
	if len(history) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "No rotation history found for secret %s\n", secretID) //nolint:errcheck
		return nil
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ROTATED_AT\tTRIGGERED_BY\tPREV_VERSION\tNEW_VERSION\tNOTES") //nolint:errcheck
	fmt.Fprintln(w, "----------\t------------\t------------\t-----------\t-----") //nolint:errcheck
	for _, h := range history {
		notes := h.Notes
		if len(notes) > 30 {
			notes = notes[:27] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\n", //nolint:errcheck
			h.RotatedAt.Format("2006-01-02 15:04"), h.TriggeredBy,
			h.PreviousVersion, h.NewVersion, notes)
	}
	w.Flush()                                                                    //nolint:errcheck,gosec
	fmt.Fprintf(cmd.OutOrStdout(), "\nFound %d rotation events\n", len(history)) //nolint:errcheck
	return nil
}

func runRotationStatus(cmd *cobra.Command) error {
	ctx := cmd.Context()
	claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
	if !ok {
		return fmt.Errorf("unauthorized: missing authentication claims")
	}
	sc, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
	if !ok || sc == nil {
		return fmt.Errorf("service container not available in context")
	}
	vaultID, err := vaultcli.RequireDataAction(ctx, cmd, sc, claims.UserID, model.ActionSecretsReadMetadata, model.OpGet)
	if err != nil {
		return fmt.Errorf("vault authorization failed: %w", err)
	}
	scope := model.NewVaultScope(vaultID, claims.UserID)
	rotSvc := sc.GetRotationService()

	due, err := rotSvc.GetDueRotations(ctx, scope)
	if err != nil {
		return fmt.Errorf("failed to get due rotations: %w", err)
	}
	reminders, err := rotSvc.GetUpcomingReminders(ctx, scope)
	if err != nil {
		return fmt.Errorf("failed to get upcoming reminders: %w", err)
	}
	policies, err := rotSvc.ListPolicies(ctx, scope)
	if err != nil {
		return fmt.Errorf("failed to list policies: %w", err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Rotation Status")                          //nolint:errcheck
	fmt.Fprintln(cmd.OutOrStdout(), "────────────────────────────────────────") //nolint:errcheck
	if len(due) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "Secrets due for rotation:") //nolint:errcheck
		for _, d := range due {
			nextRotation := "Unknown"
			if d.NextRotationAt != nil {
				nextRotation = d.NextRotationAt.Format("2006-01-02")
			}
			fmt.Fprintf(cmd.OutOrStdout(), "  - Secret %s (next: %s)\n", d.SecretID.String()[:8]+"...", nextRotation) //nolint:errcheck
		}
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "No secrets are currently due for rotation.") //nolint:errcheck
	}
	if len(reminders) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "\nUpcoming reminders:") //nolint:errcheck
		for _, r := range reminders {
			fmt.Fprintf(cmd.OutOrStdout(), "  - Secret %s (%s reminder)\n", r.SecretID.String()[:8]+"...", r.ReminderType) //nolint:errcheck
		}
	}
	if len(policies) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "\nActive rotation policies:") //nolint:errcheck
		for _, p := range policies {
			if p.Enabled {
				line := fmt.Sprintf("  - %s: every %d days", p.Name, p.IntervalDays)
				if p.AutoRotate {
					line += " (auto-rotate enabled)"
				}
				fmt.Fprintln(cmd.OutOrStdout(), line) //nolint:errcheck
			}
		}
	}
	return nil
}
