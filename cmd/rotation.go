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
	"rocketvault/internal/pwgen"
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

	// Rotate-only flags. They are package-level, like secretID and policyID
	// above, so that RunE reads them directly rather than through a flag set
	// the command's tests do not build.
	rotateValue    string
	rotateGenerate bool
	rotateLength   int
	rotateUpper    bool
	rotateLower    bool
	rotateNumbers  bool
	rotateSpecial  bool
)

// rotationCmd represents the rotation command group
var rotationCmd = &cobra.Command{
	Use:   "rotation",
	Short: "Manage secret rotation policies",
	Long: `Manage the rotation policies that govern how often a vault's secrets are
replaced. A policy carries an interval in days, a reminder lead time, and a
flag deciding whether the server rotates matching secrets on its own. A
policy does nothing until it is assigned to a secret with "assign".

Policies belong to the vault named by --vault, defaulting to "default", and
can only be assigned to secrets in that same vault. Every subcommand checks
one secrets data action in that vault: create, update, delete, assign,
unassign and rotate need
Microsoft.KeyVault/vaults/secrets/setSecret/action; list, history and status
need Microsoft.KeyVault/vaults/secrets/readMetadata/action. No global role is
checked — access comes entirely from the vault's role assignments.

Automatic rotation is carried out by the scheduler inside a running
"rocketvault serve" process, so --auto-rotate has no effect while the server
is stopped. The "rotate" subcommand is the only way to rotate from the CLI.`,
	Example: `  # Log in once; the session is cached
  rocketvault users login --username admin

  # Create a 30-day policy in the default vault
  rocketvault secrets rotation create --name <name> --interval 30

  # Assign the policy to a secret
  rocketvault secrets rotation assign --policy-id <policy-id> \
    --secret-id <secret-id>

  # Review what is due in a named vault
  rocketvault secrets rotation status --vault payments`,
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
	Use:   "create",
	Short: "Create a new rotation policy",
	Long: `Create a rotation policy in the target vault. The policy records how many
days may pass between rotations, how many days ahead of that a reminder is
raised, and whether the server's scheduler rotates assigned secrets by
itself. Creating a policy rotates nothing; it starts applying to a secret
only after "secrets rotation assign".

Requires the Microsoft.KeyVault/vaults/secrets/setSecret/action data action
in the vault named by --vault, which defaults to "default". No global role is
checked.

--reminder must be strictly smaller than --interval, or the policy is
rejected. New policies are always created enabled; there is no flag for
creating a disabled one, and the CLI cannot disable one later. The full
policy ID is printed on success — "secrets rotation list" abbreviates it.`,
	Example: `  # 30-day policy, using the default 7-day reminder
  rocketvault secrets rotation create --name <name> --interval 30

  # 90-day policy the server rotates on its own
  rocketvault secrets rotation create --name <name> --interval 90 \
    --reminder 14 --auto-rotate

  # Described policy in a named vault
  rocketvault secrets rotation create --name <name> --interval 30 \
    --description <description> --vault payments`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationCreate(cmd)
	},
}

// rotationListCmd represents the rotation list command
var rotationListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all rotation policies",
	Long: `List every rotation policy in the target vault, whoever created it — the
listing is vault-scoped, not per-user. Each row shows the interval, whether
the scheduler auto-rotates for that policy, whether the policy is enabled,
and when it was created.

Requires the Microsoft.KeyVault/vaults/secrets/readMetadata/action data
action in the vault named by --vault, which defaults to "default". No global
role is checked.

The output is always a fixed table; --output is ignored. Policy IDs are
abbreviated to their first eight characters, so take the full ID from the
output of "secrets rotation create" when a command needs --id or
--policy-id.`,
	Example: `  # List the policies in the default vault
  rocketvault secrets rotation list

  # List the policies in a named vault
  rocketvault secrets rotation list --vault payments`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationList(cmd)
	},
}

// rotationUpdateCmd represents the rotation update command
var rotationUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a rotation policy",
	Long: `Change an existing rotation policy. The stored policy is read first and only
the flags actually passed are applied, so every field left off keeps its
current value. --auto-rotate is a boolean flag: pass --auto-rotate=false to
turn scheduled rotation back off.

Requires the Microsoft.KeyVault/vaults/secrets/setSecret/action data action
in the vault named by --vault, which defaults to "default". No global role is
checked. The policy must live in that vault.

The resulting reminder days must still be strictly smaller than the resulting
interval, or the update is rejected. A new interval does not reschedule
secrets already assigned to the policy — their next rotation date is
recalculated only when they are next rotated or re-assigned.`,
	Example: `  # Change the interval and the reminder lead time
  rocketvault secrets rotation update --id <policy-id> --interval 60 \
    --reminder 14

  # Turn scheduled rotation off again
  rocketvault secrets rotation update --id <policy-id> --auto-rotate=false

  # Rename a policy in a named vault
  rocketvault secrets rotation update --id <policy-id> --name <name> \
    --vault payments`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationUpdate(cmd)
	},
}

// rotationDeleteCmd represents the rotation delete command
var rotationDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a rotation policy",
	Long: `Delete a rotation policy from the target vault. The deletion is immediate and
permanent: policies have no soft-delete or recovery, and the command does not
ask for confirmation.

Requires the Microsoft.KeyVault/vaults/secrets/setSecret/action data action
in the vault named by --vault, which defaults to "default". No global role is
checked. A policy in another vault is reported as not found.

Deleting a policy also removes its assignments to secrets and its pending
reminders, so those secrets stop being scheduled; the secrets themselves and
their values are untouched. Past rotation events stay in "secrets rotation
history" but lose their link to the deleted policy.`,
	Example: `  # Delete a policy from the default vault
  rocketvault secrets rotation delete --id <policy-id>

  # Delete a policy from a named vault
  rocketvault secrets rotation delete --id <policy-id> --vault payments`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationDelete(cmd)
	},
}

// rotationAssignCmd represents the rotation assign command
var rotationAssignCmd = &cobra.Command{
	Use:   "assign",
	Short: "Assign a policy to a secret",
	Long: `Put a secret under a rotation policy. The first rotation is scheduled for the
policy's interval from now, and if the policy has a reminder lead time a
reminder is queued for that many days before it.

Requires the Microsoft.KeyVault/vaults/secrets/setSecret/action data action
in the vault named by --vault, which defaults to "default". No global role is
checked. The secret and the policy are both read in that vault, so a
cross-vault assignment simply reports one of them as not found.

A secret may carry several policies, but the same pair cannot be assigned
twice — re-running this for a pair that is already assigned fails. To restart
a secret's clock, unassign it and assign it again.`,
	Example: `  # Assign a policy to a secret in the default vault
  rocketvault secrets rotation assign --policy-id <policy-id> \
    --secret-id <secret-id>

  # Assign a policy to a secret in a named vault
  rocketvault secrets rotation assign --policy-id <policy-id> \
    --secret-id <secret-id> --vault payments`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationAssign(cmd)
	},
}

// rotationUnassignCmd represents the rotation unassign command
var rotationUnassignCmd = &cobra.Command{
	Use:   "unassign",
	Short: "Remove a policy from a secret",
	Long: `Take a secret out of a rotation policy. The policy itself survives and stays
assigned to any other secret; only this pairing and its schedule are removed,
so the secret stops appearing in "secrets rotation status".

Requires the Microsoft.KeyVault/vaults/secrets/setSecret/action data action
in the vault named by --vault, which defaults to "default". No global role is
checked. The secret must be readable in that vault.

If the pair was never assigned, the command reports that the assignment was
not found. Reminders already queued for the pair are not cleared, and past
rotation events stay in "secrets rotation history".`,
	Example: `  # Remove a policy from a secret in the default vault
  rocketvault secrets rotation unassign --policy-id <policy-id> \
    --secret-id <secret-id>

  # Remove a policy from a secret in a named vault
  rocketvault secrets rotation unassign --policy-id <policy-id> \
    --secret-id <secret-id> --vault payments`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationUnassign(cmd)
	},
}

// rotationRotateCmd represents the rotation rotate command
var rotationRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Manually rotate a secret",
	Long: `Rotate one secret now, without waiting for its schedule. The secret's
value is replaced, the previous value is archived as a version, the version
number is incremented, a "manual" entry is added to its rotation history, and
its next rotation is pushed out by the policy's interval.

Requires the Microsoft.KeyVault/vaults/secrets/setSecret/action data action
in the vault named by --vault, which defaults to "default". No global role is
checked. The secret and the policy are both read in that vault.

The new value comes from you: pass --value to set one, or --generate to have a
random one generated with --length and the
--uppercase/--lowercase/--numbers/--special sets, exactly as "secrets
generate-password" builds them. Passing neither is an error, and passing both
is rejected. Nothing outside RocketVault is updated, so a rotated credential
must still be changed in the system that uses it.`,
	Example: `  # Rotate a secret to a value you supply
  rocketvault secrets rotation rotate --secret-id <secret-id> \
    --policy-id <policy-id> --value <new-value>

  # Rotate to a generated 32-character value with no special characters
  rocketvault secrets rotation rotate --secret-id <secret-id> \
    --policy-id <policy-id> --generate --length 32 --special=false

  # Rotate a secret in a named vault
  rocketvault secrets rotation rotate --secret-id <secret-id> \
    --policy-id <policy-id> --generate --vault payments`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationRotate(cmd)
	},
}

// rotationHistoryCmd represents the rotation history command
var rotationHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "View rotation history for a secret",
	Long: `Show every recorded rotation of one secret: when it happened, whether it was
manual or run by the scheduler, the version numbers before and after, and any
notes. Entries written by past rotations survive even after the policy that
caused them is deleted.

Requires the Microsoft.KeyVault/vaults/secrets/readMetadata/action data
action in the vault named by --vault, which defaults to "default". No global
role is checked. The secret must be readable in that vault.

Values are never shown, only version numbers. Notes longer than 30 characters
are truncated in the table, and --output is ignored. A secret that has never
been rotated prints an empty-history message rather than failing.`,
	Example: `  # Show a secret's rotation history
  rocketvault secrets rotation history --secret-id <secret-id>

  # Show it for a secret in a named vault
  rocketvault secrets rotation history --secret-id <secret-id> \
    --vault payments`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRotationHistory(cmd)
	},
}

// rotationStatusCmd represents the rotation status command
var rotationStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "View rotation status and due rotations",
	Long: `Summarise rotation for the target vault in three parts: secrets whose next
rotation date has passed under an enabled policy, reminders that have come
due and have not been acknowledged, and every enabled policy with its
interval.

Requires the Microsoft.KeyVault/vaults/secrets/readMetadata/action data
action in the vault named by --vault, which defaults to "default". No global
role is checked.

Secret IDs are abbreviated to their first eight characters, and --output is
ignored. This is a read-only report: nothing is rotated or acknowledged by
running it, and a reminder stays listed until it is acknowledged, which the
CLI has no command for.`,
	Example: `  # Show rotation status for the default vault
  rocketvault secrets rotation status

  # Show rotation status for a named vault
  rocketvault secrets rotation status --vault payments`,
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
	rotationRotateCmd.Flags().StringVar(&rotateValue, "value", "", "New secret value (mutually exclusive with --generate)")
	rotationRotateCmd.Flags().BoolVar(&rotateGenerate, "generate", false, "Generate a random new value instead of supplying one")
	rotationRotateCmd.Flags().IntVar(&rotateLength, "length", 16, "Length of the generated value (with --generate)")
	rotationRotateCmd.Flags().BoolVar(&rotateUpper, "uppercase", true, "Include uppercase letters in the generated value")
	rotationRotateCmd.Flags().BoolVar(&rotateLower, "lowercase", true, "Include lowercase letters in the generated value")
	rotationRotateCmd.Flags().BoolVar(&rotateNumbers, "numbers", true, "Include numbers in the generated value")
	rotationRotateCmd.Flags().BoolVar(&rotateSpecial, "special", true, "Include special characters in the generated value")
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
	if rotateValue == "" && !rotateGenerate {
		return fmt.Errorf("no new value: pass --value <value> to set one, or --generate to have one generated")
	}
	if rotateValue != "" && rotateGenerate {
		return fmt.Errorf("--value and --generate are mutually exclusive; pass only one")
	}

	if err := sc.GetRotationService().PerformManualRotation(ctx, secrets.ManualRotationRequest{
		SecretID: sid,
		PolicyID: pid,
		Scope:    scope,
		NewValue: rotateValue,
		Generate: rotateGenerate,
		GenerateOpts: pwgen.Options{
			Length:  rotateLength,
			Upper:   rotateUpper,
			Lower:   rotateLower,
			Numbers: rotateNumbers,
			Special: rotateSpecial,
		},
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
