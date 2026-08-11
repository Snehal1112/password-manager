# Vault CLI Extension — Plan 05: Certificates Command Wiring

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `--vault` resolution and per-vault authorization into all five `cmd/certificates` commands (`list`, `get`, `delete`, `update`, `renew`), closing the last gap of the `vault-cli` extension series.

**Architecture:** Each command adds one `vaultcli.RequireDataAction` call (built in Plan 01) immediately before its first `CertificateService` call, replacing `model.NewOwnerScope(uuid.Nil, claims.UserID)` with `model.NewVaultScope(vaultID, claims.UserID)`. `list`/`get`/`delete` are pure plumbing onto a backend that is already vault-scoped. `update`/`renew` additionally rely on Plan 04's backend fixes: `UpdateCertificateRequest.Scope` is already fully respected by `CertificateService.UpdateCertificate` (no service-layer change needed), and `RenewCertificate`'s frozen signature is `RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*CreateCertificateResult, error)`.

**Tech Stack:** Go, Cobra, `github.com/stretchr/testify/mock`, the `cmd/vaultcli` and `cmd/testutils` packages built by Plan 01.

## Global Constraints

- Design doc: `docs/superpowers/specs/2026-08-11-vault-cli-extension-design.md` — read in full before starting.
- Depends on Plan 01 (`docs/superpowers/plans/2026-08-11-vault-cli-01-shared-primitives.md`, produces `vaultcli.ResolveVaultID`/`vaultcli.RequireDataAction`/`testutils.MockRoleAssignmentService`) and Plan 04 (`docs/superpowers/plans/2026-08-11-vault-cli-04-certificate-backend-fixes.md`, produces `RenewCertificate`'s frozen `(ctx, certID, scope, validityDays)` signature and confirms `UpdateCertificate` already honors `req.Scope`) — both must have landed before starting this plan.
- This is the final plan in the 5-plan `vault-cli` series. Task 3's last step updates `README.md`'s Roadmap to mark all three `--vault`/certificate-scoping items shipped, closing out the whole series (not just this plan's own certificate scope).
- No admin short-circuit anywhere in this plan — `vaultcli.RequireDataAction` (Plan 01) has none, and none is introduced here. Data-plane access has no bypass for the global admin role, matching `PolicyMiddleware`'s HTTP-side behavior.
- Every touched command's existing legacy `common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleCertificateManager)` gate on `delete`/`update`/`renew` stays exactly as-is. This plan adds the new vault-authorization check **alongside** it, not instead of it — the legacy check gates a coarser, different concern.
- Each command hardcodes its own `model.DataAction` constant directly (`vaultcli.RequireDataAction(ctx, cmd, sc, claims.UserID, model.ActionCertificatesRead, model.OpGet)`) — no derivation via `MapRouteToDataAction`.
- `go build ./...` and `go vet ./...` must pass after every task.
- `model.DataAction` per command (verified against `internal/services/authorization/data_actions.go`):

  | Command | Action | Op |
  |---|---|---|
  | list | `model.ActionCertificatesRead` | `model.OpGet` |
  | get | `model.ActionCertificatesRead` | `model.OpGet` |
  | delete | `model.ActionCertificatesDelete` | `model.OpDelete` |
  | update | `model.ActionCertificatesUpdate` | `model.OpSet` |
  | renew | `model.ActionCertificatesCreate` | `model.OpRenew` |
- `vaultcli.RequireDataAction` gained a `op model.PolicyOperation` parameter after Plan 01's final review found it needed to also check the `access_policies` explicit-deny override — see `docs/superpowers/specs/2026-08-11-vault-cli-extension-design.md`'s "Access-policy explicit-deny in the CLI adapter" section for the full per-command mapping table (reproduced above for this plan's commands).

---

### Task 1: `list`, `get`, `delete` — pure plumbing

**Files:**
- Modify: `cmd/certificates/list.go`
- Modify: `cmd/certificates/get.go`
- Modify: `cmd/certificates/delete.go`
- Modify: `cmd/certificates/certs_cmd_test.go` (List/Get/Delete test sections only)

**Interfaces:**
- Consumes: `vaultcli.RequireDataAction(ctx context.Context, cmd *cobra.Command, sc container.ServiceContainerInterface, principalID uuid.UUID, action model.DataAction, op model.PolicyOperation) (vaultID uuid.UUID, err error)` (Plan 01, `cmd/vaultcli/vault.go`); `model.NewVaultScope(vaultID, actorID uuid.UUID) model.Scope` (existing, `model/scope.go`); `testutils.NewTestContext(t) *testutils.TestContext` and `testutils.MockRoleAssignmentService` (Plan 01, `cmd/testutils/test_utils.go`).
- Produces: vault-scoped, authorization-checked `certificate list`, `certificate get`, `certificate delete` commands. Not consumed by Task 2/3 (separate files), but completes the certificates half of the design's Scope section alongside them.

- [ ] **Step 1: Update the `list` tests to expect vault-scoped, authorization-checked behavior**

In `cmd/certificates/certs_cmd_test.go`, replace `TestCertListCmd_SuccessTwoCerts`, `TestCertListCmd_EmptyList`, `TestCertListCmd_ServiceError`, and `TestCertListCmd_NoFormatter` with:

```go
func TestCertListCmd_SuccessTwoCerts(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certs := []model.Certificate{
		{ID: uuid.New(), UserID: tc.TestUserID, Name: "cert1", CreatedAt: time.Now(), Enabled: true},
		{ID: uuid.New(), UserID: tc.TestUserID, Name: "cert2", CreatedAt: time.Now(), Enabled: true},
	}
	certSvc.On("ListCertificates", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), repositories.CertificateFilter{}).Return(certs, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, buf := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	certSvc.AssertExpectations(t)
}

func TestCertListCmd_EmptyList(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certSvc.On("ListCertificates", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), repositories.CertificateFilter{}).Return([]model.Certificate{}, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleUser}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertListCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certSvc.On("ListCertificates", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), repositories.CertificateFilter{}).Return(nil, fmt.Errorf("db error"))

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleSecretsManager}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to list certificates")
	certSvc.AssertExpectations(t)
}

func TestCertListCmd_NoFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certSvc.On("ListCertificates", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), repositories.CertificateFilter{}).Return([]model.Certificate{}, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleUser}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	// No formatter.

	cmd, _ := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	certSvc.AssertExpectations(t)
}
```

Add a new test directly after `TestCertListCmd_NoFormatter`:

```go
func TestCertListCmd_Denied(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(listCmd.RunE, nil)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to list certificates")
	certSvc.AssertNotCalled(t, "ListCertificates", mock.Anything, mock.Anything, mock.Anything)
}
```

- [ ] **Step 2: Update the `get` tests the same way**

Replace `TestCertGetCmd_Success`, `TestCertGetCmd_ServiceError`, and `TestCertGetCmd_NoFormatter` with:

```go
func TestCertGetCmd_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	expiresAt := time.Now().Add(365 * 24 * time.Hour)
	cert := &model.Certificate{
		ID: certID, UserID: tc.TestUserID, Name: "mycert",
		Tags: []string{"ssl"}, CreatedAt: time.Now(), ExpiresAt: &expiresAt,
		AutoRenew: true, Enabled: true,
	}
	certSvc.On("GetCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(cert, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, buf := newCertCmd(getCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	certSvc.AssertExpectations(t)
}

func TestCertGetCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	certSvc.On("GetCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(nil, fmt.Errorf("not found"))

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(getCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to get certificate")
	certSvc.AssertExpectations(t)
}

func TestCertGetCmd_NoFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	cert := &model.Certificate{
		ID: certID, UserID: tc.TestUserID, Name: "k",
		CreatedAt: time.Now(), Enabled: true,
	}
	certSvc.On("GetCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(cert, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	// No formatter.

	cmd, _ := newCertCmd(getCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	certSvc.AssertExpectations(t)
}
```

Add a new test directly after `TestCertGetCmd_NoFormatter`:

```go
func TestCertGetCmd_Denied(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())

	cmd, _ := newCertCmd(getCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to get certificate")
	certSvc.AssertNotCalled(t, "GetCertificate", mock.Anything, mock.Anything, mock.Anything)
}
```

- [ ] **Step 3: Update the `delete` tests the same way**

Replace `TestCertDeleteCmd_Success` and `TestCertDeleteCmd_ServiceError` with:

```go
func TestCertDeleteCmd_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	certSvc.On("DeleteCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newCertCmd(deleteCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertDeleteCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	certSvc.On("DeleteCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(fmt.Errorf("delete failed"))

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newCertCmd(deleteCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to delete certificate")
	certSvc.AssertExpectations(t)
}
```

Add a new test directly after `TestCertDeleteCmd_ServiceError`:

```go
func TestCertDeleteCmd_Denied(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cmd, _ := newCertCmd(deleteCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to delete certificate")
	certSvc.AssertNotCalled(t, "DeleteCertificate", mock.Anything, mock.Anything, mock.Anything)
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `go test ./cmd/certificates/... -run 'TestCertListCmd|TestCertGetCmd|TestCertDeleteCmd' -v`
Expected: FAIL. The `_Success`/`_ServiceError`/`_NoFormatter`/`_EmptyList` tests fail because `certSvc` still receives `model.NewOwnerScope(uuid.Nil, ...)` calls from unmodified production code, not the `model.NewVaultScope(...)` the updated mocks now expect (testify reports "mock: I don't know what to return because the method call was unexpected"). The new `_Denied` tests fail because production code has no authorization check yet, so `certSvc.AssertNotCalled` fails — the service method **was** called.

- [ ] **Step 5: Wire `list.go`**

Replace the full contents of `cmd/certificates/list.go` with:

```go
/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List certificates",
	Long:  `List all X.509 certificates for the authenticated user. Admins can list all certificates.`,
	Example: `  # List all certificates
  rocketvault certificate list \
    --username admin --password admin123 --totp-code <code>`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)

		// Get service container from context
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "list_certificates", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		certService := serviceContainer.GetCertificateService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionCertificatesRead, model.OpGet)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "list_certificates", "failed", fmt.Sprintf("authorization failed: %s", err), err)
			return fmt.Errorf("failed to list certificates: %w", err)
		}

		certs, err := certService.ListCertificates(ctx, model.NewVaultScope(vaultID, claims.UserID), repositories.CertificateFilter{})
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "list_certificates", "failed", fmt.Sprintf("failed to list certificates: %s", err), err)
			return fmt.Errorf("failed to list certificates: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "list_certificates", "success", fmt.Sprintf("listed %d certificates", len(certs)))

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}

		headers := []string{"ID", "Name", "Tags", "Expires", "AutoRenew", "Created"}
		rows := make([][]string, len(certs))
		for i, c := range certs {
			rows[i] = []string{
				c.ID.String(),
				c.Name,
				strings.Join(c.Tags, ","),
				formatOptionalTime(c.ExpiresAt),
				strconv.FormatBool(c.AutoRenew),
				c.CreatedAt.Format(time.RFC3339),
			}
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, rows)
	},
}

// formatOptionalTime formats a pointer to time.Time as RFC3339, returning empty string for nil.
func formatOptionalTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

// InitCertificatesList initializes the list command for certificates.
func InitCertificatesList(certificatesCmd *cobra.Command) *cobra.Command {
	certificatesCmd.AddCommand(listCmd)
	return certificatesCmd
}
```

Note: `"github.com/google/uuid"` is removed from the import block — after this change nothing in `list.go` references the `uuid` package anymore.

- [ ] **Step 6: Wire `get.go`**

Replace the full contents of `cmd/certificates/get.go` with:

```go
/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Retrieve a certificate",
	Long:  `Retrieve details of an X.509 certificate by its UUID. Accessible by the certificate's owner or users with the admin role.`,
	Example: `  # Get a certificate by ID
  rocketvault certificate get <cert-id> \
    --username admin --password admin123 --totp-code <code>`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		certID, err := uuid.Parse(args[0])
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "get_certificate", "failed", fmt.Sprintf("invalid certificate ID: %s", err), err)
			return fmt.Errorf("invalid certificate ID: %w", err)
		}

		// Get service container from context
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "get_certificate", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		certService := serviceContainer.GetCertificateService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionCertificatesRead, model.OpGet)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "get_certificate", "failed", fmt.Sprintf("authorization failed: %s", err), err)
			return fmt.Errorf("failed to get certificate: %w", err)
		}

		cert, err := certService.GetCertificate(ctx, certID, model.NewVaultScope(vaultID, claims.UserID))
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "get_certificate", "failed", fmt.Sprintf("failed to get certificate: %s", err), err)
			return fmt.Errorf("failed to get certificate: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "get_certificate", "success", fmt.Sprintf("certificate retrieved: %s", cert.Name))

		fmtr, ok := ctx.Value(common.OutputFormatterKey).(formatter.Formatter)
		if !ok {
			return fmt.Errorf("output formatter not available in context")
		}

		headers := []string{"ID", "Name", "Tags", "Expires", "AutoRenew", "Created"}
		row := []string{
			cert.ID.String(),
			cert.Name,
			strings.Join(cert.Tags, ","),
			formatOptionalTime(cert.ExpiresAt),
			strconv.FormatBool(cert.AutoRenew),
			cert.CreatedAt.Format(time.RFC3339),
		}
		return fmtr.Write(cmd.OutOrStdout(), headers, [][]string{row})
	},
}

// InitCertificatesGet initializes the get command for certificates.
func InitCertificatesGet(certificatesCmd *cobra.Command) *cobra.Command {
	certificatesCmd.AddCommand(getCmd)
	return certificatesCmd
}
```

- [ ] **Step 7: Wire `delete.go`**

Replace the full contents of `cmd/certificates/delete.go` with:

```go
/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// deleteCmd represents the delete command
var deleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a certificate",
	Long:  `Delete an X.509 certificate by its UUID. Requires admin or certificate_manager role.`,
	Example: `  # Delete a certificate
  rocketvault certificate delete <cert-id> \
    --username admin --password admin123 --totp-code <code>`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		if !common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleCertificateManager) {
			log.LogAuditError(claims.UserID.String(), "delete_certificate", "failed", "forbidden: requires admin or certificate_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or certificate_manager role")
		}

		certID, err := uuid.Parse(args[0])
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "delete_certificate", "failed", fmt.Sprintf("invalid certificate ID: %s", err), err)
			return fmt.Errorf("invalid certificate ID: %w", err)
		}

		// Get service container from context
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "delete_certificate", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		certService := serviceContainer.GetCertificateService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionCertificatesDelete, model.OpDelete)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "delete_certificate", "failed", fmt.Sprintf("authorization failed: %s", err), err)
			return fmt.Errorf("failed to delete certificate: %w", err)
		}

		err = certService.DeleteCertificate(ctx, certID, model.NewVaultScope(vaultID, claims.UserID))
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "delete_certificate", "failed", fmt.Sprintf("failed to delete certificate: %s", err), err)
			return fmt.Errorf("failed to delete certificate: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "delete_certificate", "success", fmt.Sprintf("certificate deleted: %s", certID))
		fmt.Printf("Certificate deleted successfully: %s\n", certID)
		return nil
	},
}

// InitCertificatesDelete initializes the delete command for certificates.
func InitCertificatesDelete(certificatesCmd *cobra.Command) *cobra.Command {
	certificatesCmd.AddCommand(deleteCmd)
	return certificatesCmd
}
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `go test ./cmd/certificates/... -run 'TestCertListCmd|TestCertGetCmd|TestCertDeleteCmd' -v`
Expected: PASS.

- [ ] **Step 9: Full build/vet check**

Run: `go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 10: Commit**

```bash
git add cmd/certificates/list.go cmd/certificates/get.go cmd/certificates/delete.go cmd/certificates/certs_cmd_test.go
git commit -m "feat(cmd/certificates): wire --vault + authorization into list/get/delete"
```

---

### Task 2: `update` — vault-scoped update, reusing Plan 04's backend fix

**Files:**
- Modify: `cmd/certificates/update.go`
- Modify: `cmd/certificates/certs_cmd_test.go` (Update test section only)

**Interfaces:**
- Consumes: `vaultcli.RequireDataAction` (Plan 01, as in Task 1); `certServices.UpdateCertificateRequest{CertID, Scope, Name, Tags, AutoRenew, RenewalDays}` (existing, `internal/services/certificates/certificate_service.go`) — Plan 04 confirmed `CertificateService.UpdateCertificate` already authorizes strictly via `req.Scope`, with no hardcoded scope in the service method itself, so no service-layer change is needed here — only the CLI-constructed `Scope` value changes from owner to vault.
- Produces: vault-scoped, authorization-checked `certificate update` command.

- [ ] **Step 1: Update the `update` tests to expect vault-scoped, authorization-checked behavior**

In `cmd/certificates/certs_cmd_test.go`, replace `TestCertUpdateCmd_SuccessWithNameUpdate`, `TestCertUpdateCmd_SuccessWithAutoRenewFlagChanged`, `TestCertUpdateCmd_SuccessWithRenewalDaysFlagChanged`, and `TestCertUpdateCmd_ServiceError` with:

```go
func TestCertUpdateCmd_SuccessWithNameUpdate(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	certSvc.On("UpdateCertificate", mock.Anything, mock.MatchedBy(func(r certServices.UpdateCertificateRequest) bool {
		return r.CertID == certID && r.Scope == model.NewVaultScope(tc.TestVaultID, tc.TestUserID) && r.Name != nil && *r.Name == "newname"
	})).Return(nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSetCert(map[string]interface{}{"cert-update-name": "newname", "cert-update-tags": ""})
	defer cleanup()

	// Use a fresh command with args so viper picks up the name correctly.
	cmd := &cobra.Command{Use: "test", Args: cobra.ExactArgs(1), RunE: updateCmd.RunE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetArgs([]string{certID.String()})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertUpdateCmd_SuccessWithAutoRenewFlagChanged(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	certSvc.On("UpdateCertificate", mock.Anything, mock.MatchedBy(func(r certServices.UpdateCertificateRequest) bool {
		return r.CertID == certID && r.AutoRenew != nil && *r.AutoRenew == true
	})).Return(nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSetCert(map[string]interface{}{"cert-update-name": "", "cert-update-tags": ""})
	defer cleanup()

	// Register flags and set args so that --auto-renew is marked Changed.
	cmd := &cobra.Command{Use: "test", Args: cobra.ExactArgs(1), RunE: updateCmd.RunE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetArgs([]string{certID.String(), "--auto-renew=true"})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertUpdateCmd_SuccessWithRenewalDaysFlagChanged(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	certSvc.On("UpdateCertificate", mock.Anything, mock.MatchedBy(func(r certServices.UpdateCertificateRequest) bool {
		return r.CertID == certID && r.RenewalDays != nil && *r.RenewalDays == 60
	})).Return(nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSetCert(map[string]interface{}{"cert-update-name": "", "cert-update-tags": ""})
	defer cleanup()

	cmd := &cobra.Command{Use: "test", Args: cobra.ExactArgs(1), RunE: updateCmd.RunE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetArgs([]string{certID.String(), "--renewal-days=60"})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertUpdateCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	certSvc.On("UpdateCertificate", mock.Anything, mock.Anything).Return(fmt.Errorf("update failed"))

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSetCert(map[string]interface{}{"cert-update-name": "n", "cert-update-tags": ""})
	defer cleanup()

	cmd := &cobra.Command{Use: "test", Args: cobra.ExactArgs(1), RunE: updateCmd.RunE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetArgs([]string{certID.String()})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to update certificate")
	certSvc.AssertExpectations(t)
}
```

Add a new test directly after `TestCertUpdateCmd_ServiceError`:

```go
func TestCertUpdateCmd_Denied(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSetCert(map[string]interface{}{"cert-update-name": "n", "cert-update-tags": ""})
	defer cleanup()

	cmd := &cobra.Command{Use: "test", Args: cobra.ExactArgs(1), RunE: updateCmd.RunE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("tags", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("renewal-days", 0, "")
	cmd.SetArgs([]string{certID.String()})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to update certificate")
	certSvc.AssertNotCalled(t, "UpdateCertificate", mock.Anything, mock.Anything)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/certificates/... -run TestCertUpdateCmd -v`
Expected: FAIL — the success tests fail because `req.Scope` is still `model.NewOwnerScope(uuid.Nil, ...)` in production code, not matching the updated `mock.MatchedBy`/vault-scope expectations, and `TestCertUpdateCmd_Denied` fails because `UpdateCertificate` **was** called (no authorization check exists yet).

- [ ] **Step 3: Wire `update.go`**

Replace the full contents of `cmd/certificates/update.go` with:

```go
/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/logging"
	certServices "rocketvault/internal/services/certificates"
	"rocketvault/model"
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update <id>",
	Short: "Update certificate metadata",
	Long:  `Update metadata for an X.509 certificate (name, tags). Requires admin or certificate_manager role.`,
	Example: `  # Update certificate metadata
  rocketvault certificate update <cert-id> --name "Updated name" \
    --tags prod,secure \
    --username admin --password admin123 --totp-code <code>`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		if !common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleCertificateManager) {
			log.LogAuditError(claims.UserID.String(), "update_certificate", "failed", "forbidden: requires admin or certificate_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or certificate_manager role")
		}

		certID, err := uuid.Parse(args[0])
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "update_certificate", "failed", fmt.Sprintf("invalid certificate ID: %s", err), err)
			return fmt.Errorf("invalid certificate ID: %w", err)
		}

		name := viper.GetString("cert-update-name")
		tagsStr := viper.GetString("cert-update-tags")

		// Only pass auto-renew if the flag was explicitly set by the caller.
		var autoRenewPtr *bool
		if cmd.Flags().Changed("auto-renew") {
			v, _ := cmd.Flags().GetBool("auto-renew")
			autoRenewPtr = &v
		}

		// Only pass renewal-days if the flag was explicitly set by the caller.
		var renewalDaysPtr *int
		if cmd.Flags().Changed("renewal-days") {
			v, _ := cmd.Flags().GetInt("renewal-days")
			renewalDaysPtr = &v
		}

		var tags []string
		if tagsStr != "" {
			tags = strings.Split(tagsStr, ",")
			for i, tag := range tags {
				tags[i] = strings.TrimSpace(tag)
			}
		}

		// Get service container from context
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "update_certificate", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		certService := serviceContainer.GetCertificateService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionCertificatesUpdate, model.OpSet)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "update_certificate", "failed", fmt.Sprintf("authorization failed: %s", err), err)
			return fmt.Errorf("failed to update certificate: %w", err)
		}

		var namePtr *string
		if name != "" {
			namePtr = &name
		}

		req := certServices.UpdateCertificateRequest{
			CertID:      certID,
			Scope:       model.NewVaultScope(vaultID, claims.UserID),
			Name:        namePtr,
			Tags:        tags,
			AutoRenew:   autoRenewPtr,
			RenewalDays: renewalDaysPtr,
		}

		err = certService.UpdateCertificate(ctx, req)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "update_certificate", "failed", fmt.Sprintf("failed to update certificate: %s", err), err)
			return fmt.Errorf("failed to update certificate: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "update_certificate", "success", fmt.Sprintf("certificate updated: %s", certID))
		fmt.Printf("Certificate updated successfully: %s\n", certID)
		return nil
	},
}

// InitCertificatesUpdate initializes the update command for certificates.
func InitCertificatesUpdate(certificatesCmd *cobra.Command) *cobra.Command {
	certificatesCmd.AddCommand(updateCmd)

	updateCmd.Flags().String("name", "", "Updated name for the certificate")
	updateCmd.Flags().String("tags", "", "Comma-separated tags for the certificate")
	updateCmd.Flags().Bool("auto-renew", false, "Enable or disable auto-renewal")
	updateCmd.Flags().Int("renewal-days", 0, "Days before expiry to trigger renewal")
	viper.BindPFlag("cert-update-name", updateCmd.Flags().Lookup("name"))
	viper.BindPFlag("cert-update-tags", updateCmd.Flags().Lookup("tags"))

	return certificatesCmd
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./cmd/certificates/... -run TestCertUpdateCmd -v`
Expected: PASS.

- [ ] **Step 5: Full build/vet check**

Run: `go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add cmd/certificates/update.go cmd/certificates/certs_cmd_test.go
git commit -m "feat(cmd/certificates): wire --vault + authorization into update"
```

---

### Task 3: `renew` — vault-scoped renewal on Plan 04's new signature, plus roadmap close-out

**Files:**
- Modify: `cmd/certificates/renew.go`
- Modify: `cmd/certificates/certs_cmd_test.go` (Renew test section, plus the `certCmdCertService.RenewCertificate` mock method if it does not already match the frozen signature)
- Modify: `README.md` (Roadmap section)

**Interfaces:**
- Consumes: `vaultcli.RequireDataAction` (Plan 01, as in Tasks 1–2); `CertificateService.RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*CreateCertificateResult, error)` — Plan 04's frozen signature.
- Produces: vault-scoped, authorization-checked `certificate renew` command; a `README.md` Roadmap that reflects all five certificate commands (plus keys) as shipped, closing the `vault-cli` extension series.

- [ ] **Step 1: Confirm the test double already matches Plan 04's frozen `RenewCertificate` signature**

Read `cmd/certificates/certs_cmd_test.go` and find the `certCmdCertService.RenewCertificate` method. Because `certsTestContainer.certSvc` is statically typed as `certServices.CertificateService`, Plan 04 could not have compiled without already updating this method to the frozen signature — but confirm before proceeding. It must read:

```go
func (m *certCmdCertService) RenewCertificate(ctx context.Context, certID uuid.UUID, scope model.Scope, validityDays int) (*certServices.CreateCertificateResult, error) {
	args := m.Called(ctx, certID, scope, validityDays)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*certServices.CreateCertificateResult), args.Error(1)
}
```

If it does not read exactly this (e.g. it still takes a bare `userID uuid.UUID` third parameter), replace it with the code above before continuing — the rest of this task's diffs assume this exact shape.

- [ ] **Step 2: Update the `renew` tests to expect vault-scoped, authorization-checked behavior**

In `cmd/certificates/certs_cmd_test.go`, replace `TestCertRenewCmd_Success` and `TestCertRenewCmd_ServiceError` with:

```go
func TestCertRenewCmd_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	result := &certServices.CreateCertificateResult{
		CertID:    uuid.New(),
		Name:      "renewed",
		CreatedAt: time.Now(),
	}
	certSvc.On("RenewCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), 365).Return(result, nil)

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSetCert(map[string]interface{}{"cert-renew-validity-days": 365})
	defer cleanup()

	cmd, _ := newCertCmd(renewCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	certSvc.AssertExpectations(t)
}

func TestCertRenewCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()
	certSvc.On("RenewCertificate", mock.Anything, certID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), 180).Return(nil, fmt.Errorf("renew failed"))

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSetCert(map[string]interface{}{"cert-renew-validity-days": 180})
	defer cleanup()

	cmd, _ := newCertCmd(renewCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to renew certificate")
	certSvc.AssertExpectations(t)
}
```

Add a new test directly after `TestCertRenewCmd_ServiceError`:

```go
func TestCertRenewCmd_Denied(t *testing.T) {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	certID := uuid.New()

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	sc := &certsTestContainer{
		MockServiceContainer: tc.MockContainer,
		certSvc:              certSvc,
	}
	claims := &model.Claims{UserID: tc.TestUserID, Role: model.RoleAdmin}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)

	cleanup := viperSetCert(map[string]interface{}{"cert-renew-validity-days": 365})
	defer cleanup()

	cmd, _ := newCertCmd(renewCmd.RunE, []string{certID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to renew certificate")
	certSvc.AssertNotCalled(t, "RenewCertificate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./cmd/certificates/... -run TestCertRenewCmd -v`
Expected: FAIL. `TestCertRenewCmd_Success`/`_ServiceError` fail because production code still passes an owner-scoped (or bare-`userID`, depending on Plan 04's exact intermediate state) argument that does not match the `model.NewVaultScope(tc.TestVaultID, tc.TestUserID)` expectation. `TestCertRenewCmd_Denied` fails because `RenewCertificate` **was** called (no authorization check exists yet on this command).

- [ ] **Step 4: Wire `renew.go`**

Read `cmd/certificates/renew.go` first — by this point in the series Plan 04 has already changed the `RenewCertificate` call site to pass a `model.Scope` as its third argument (a minimal compile-fix for the new signature, not a vault-scoped call), most likely `certService.RenewCertificate(ctx, certID, model.NewOwnerScope(uuid.Nil, claims.UserID), validityDays)` — the same owner-scope pattern every other certificate command used before this plan touched them. Regardless of the exact intermediate text, replace the **entire file** with the following final version, which is what must result:

```go
/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"rocketvault/cmd/vaultcli"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// renewCmd represents the renew command
var renewCmd = &cobra.Command{
	Use:   "renew <id>",
	Short: "Renew a certificate",
	Long:  `Renew an expiring X.509 certificate with a new validity period. Requires admin or certificate_manager role.`,
	Example: `  # Renew a certificate
  rocketvault certificate renew <cert-id> --validity-days 365 \
    --username admin --password admin123 --totp-code <code>`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		claims, ok := ctx.Value(common.ClaimsKey).(*model.Claims)
		if !ok {
			return fmt.Errorf("unauthorized: missing authentication claims")
		}

		log := ctx.Value(common.LogKey).(*logging.Logger)
		if !common.HasRequiredRole(claims.Role, model.RoleAdmin, model.RoleCertificateManager) {
			log.LogAuditError(claims.UserID.String(), "renew_certificate", "failed", "forbidden: requires admin or certificate_manager role", nil)
			return fmt.Errorf("forbidden: requires admin or certificate_manager role")
		}

		certID, err := uuid.Parse(args[0])
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "renew_certificate", "failed", fmt.Sprintf("invalid certificate ID: %s", err), err)
			return fmt.Errorf("invalid certificate ID: %w", err)
		}

		validityDays := viper.GetInt("cert-renew-validity-days")
		if validityDays <= 0 {
			log.LogAuditError(claims.UserID.String(), "renew_certificate", "failed", "validity-days must be greater than 0", nil)
			return fmt.Errorf("validity-days must be greater than 0")
		}

		// Get service container from context
		serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
		if !ok || serviceContainer == nil {
			log.LogAuditError(claims.UserID.String(), "renew_certificate", "failed", "service container not available", nil)
			return fmt.Errorf("service container not available in context")
		}
		certService := serviceContainer.GetCertificateService()

		vaultID, err := vaultcli.RequireDataAction(ctx, cmd, serviceContainer, claims.UserID, model.ActionCertificatesCreate, model.OpRenew)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "renew_certificate", "failed", fmt.Sprintf("authorization failed: %s", err), err)
			return fmt.Errorf("failed to renew certificate: %w", err)
		}

		result, err := certService.RenewCertificate(ctx, certID, model.NewVaultScope(vaultID, claims.UserID), validityDays)
		if err != nil {
			log.LogAuditError(claims.UserID.String(), "renew_certificate", "failed", fmt.Sprintf("failed to renew certificate: %s", err), err)
			return fmt.Errorf("failed to renew certificate: %w", err)
		}

		log.LogAuditInfo(claims.UserID.String(), "renew_certificate", "success", fmt.Sprintf("certificate renewed: %s, new ID: %s", certID, result.CertID))
		fmt.Printf("Certificate renewed successfully!\nOld Certificate ID: %s\nNew Certificate ID: %s\nValidity: %d days\n",
			certID, result.CertID, validityDays)
		return nil
	},
}

// InitCertificatesRenew initializes the renew command for certificates.
func InitCertificatesRenew(certificatesCmd *cobra.Command) *cobra.Command {
	certificatesCmd.AddCommand(renewCmd)

	renewCmd.Flags().Int("validity-days", 365, "Certificate validity period in days")
	viper.BindPFlag("cert-renew-validity-days", renewCmd.Flags().Lookup("validity-days"))

	return certificatesCmd
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./cmd/certificates/... -v`
Expected: PASS — the full package, not just the renew subset, to catch any regression in Tasks 1–2's tests from this final file's changes.

- [ ] **Step 6: Full build/vet check**

Run: `go build ./... && go vet ./...`
Expected: clean.

- [ ] **Step 7: Commit the renew wiring**

```bash
git add cmd/certificates/renew.go cmd/certificates/certs_cmd_test.go
git commit -m "feat(cmd/certificates): wire --vault + authorization into renew"
```

- [ ] **Step 8: Close out the `vault-cli` series in `README.md`'s Roadmap**

In `README.md`, find the three `Planned` Roadmap lines added 2026-08-11 (currently just above `## Acknowledgments`):

```markdown
- [ ] Extend `--vault` CLI support to `keys` (create/get/list/update/delete/rotate/wrap/unwrap) — pure CLI wiring, every one of these already has a vault-scoped HTTP path and vault-aware service method, needs zero new service/repository code
- [ ] Extend `--vault` CLI support to `certificates` `list`/`get`/`delete` — same as keys, backend is already vault-scoped
- [ ] Make certificate `update` and `renew` genuinely vault-scoped (currently hardcoded owner-only at the API/service level, not just missing a CLI flag) before extending `--vault` to them
```

Remove these three lines from the `Planned` section entirely, and add the following three lines to the end of the `Shipped`-style list that precedes `### Planned` (directly after the existing `- [x] Key delete and all crypto operations...` line):

```markdown
- [x] Extend `--vault` CLI support to `keys` (create/get/list/update/delete/rotate/wrap/unwrap) — pure CLI wiring, every one of these already had a vault-scoped HTTP path and vault-aware service method
- [x] Extend `--vault` CLI support to `certificates` `list`/`get`/`delete` — same as keys, backend was already vault-scoped
- [x] Certificate `update` and `renew` made genuinely vault-scoped (previously hardcoded owner-only at the API/service level) — `--vault` now works on every certificate command
```

This assumes the `keys` half of this Roadmap item was already shipped by the time this plan (05, the last in the series) runs — this final step closes out the Roadmap for the whole `vault-cli` series, not just the certificates work done in this plan.

- [ ] **Step 9: Commit the README update**

```bash
git add README.md
git commit -m "docs(readme): close out the vault-cli extension series in the Roadmap"
```
