/*
Copyright © 2025 Snehal Dangroshiya
*/

package certificates

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/model"
)

// newCertRotationPolicyCmd creates a minimal test command wired with the
// rotation-policy subcommands' flags, mirroring newCertCmd but with the
// extra flags rotation-policy set needs.
func newCertRotationPolicyCmd(runE func(*cobra.Command, []string) error, args []string) (*cobra.Command, *bytes.Buffer) {
	cmd, buf := newCertCmd(runE, args)
	cmd.Args = cobra.ExactArgs(1)
	cmd.Flags().Int("validity-months", 0, "")
	cmd.Flags().String("key-type", "", "")
	cmd.Flags().Int("key-size", 0, "")
	cmd.Flags().String("curve", "", "")
	cmd.Flags().String("subject", "", "")
	cmd.Flags().String("sans", "", "")
	cmd.Flags().Bool("auto-renew", false, "")
	cmd.Flags().Int("days-before-expiry", 0, "")
	cmd.Flags().String("issuer-name", "", "")
	return cmd, buf
}

// newCertRotationPolicyNoArgCmd creates a minimal test command for the
// no-argument rotation-policy subcommands (list, status).
func newCertRotationPolicyNoArgCmd(runE func(*cobra.Command, []string) error) (*cobra.Command, *bytes.Buffer) {
	return newCertCmd(runE, nil)
}

// rotationPolicyFixture bundles a fresh TestContext, a certificate-service
// mock and an authenticated admin context, so each test case only has to
// state the mock expectations and flags it cares about.
type rotationPolicyFixture struct {
	tc      *testutils.TestContext
	certSvc *certCmdCertService
	ctx     context.Context
}

func newRotationPolicyFixture(t *testing.T) *rotationPolicyFixture {
	tc := testutils.NewTestContext(t)
	certSvc := &certCmdCertService{}
	sc := &certsTestContainer{MockServiceContainer: tc.MockContainer, certSvc: certSvc}
	claims := &model.Claims{UserID: tc.TestUserID, Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newCertFmtr())
	return &rotationPolicyFixture{tc: tc, certSvc: certSvc, ctx: ctx}
}

// scope returns the vault scope the rotation-policy commands should
// authorize against, given this fixture's user and default vault.
func (f *rotationPolicyFixture) scope() model.Scope {
	return model.NewVaultScope(f.tc.TestVaultID, f.tc.TestUserID)
}

// deny replaces the fixture's role-assignment mock with one that denies
// every data action, exercising the vault-authorization-failed path.
func (f *rotationPolicyFixture) deny() {
	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	f.tc.MockContainer.RoleAssignmentService = denyRoles
}

// ========== rotation-policy get ==========

func TestCertRotationPolicyGetCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newCertRotationPolicyCmd(rotationPolicyGetCmd.RunE, []string{uuid.New().String()})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCertRotationPolicyGetCmd_InvalidUUID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cmd, _ := newCertRotationPolicyCmd(rotationPolicyGetCmd.RunE, []string{"not-a-uuid"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid certificate ID")
}

func TestCertRotationPolicyGetCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cmd, _ := newCertRotationPolicyCmd(rotationPolicyGetCmd.RunE, []string{uuid.New().String()})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCertRotationPolicyGetCmd_Success(t *testing.T) {
	f := newRotationPolicyFixture(t)
	certID := uuid.New()
	policy := &model.CertificatePolicy{
		CertificateID:    certID,
		ValidityMonths:   12,
		KeyType:          "RSA",
		KeySize:          2048,
		Subject:          "CN=example.com",
		AutoRenew:        true,
		DaysBeforeExpiry: 30,
		UpdatedAt:        time.Now(),
	}
	f.certSvc.On("GetCertificatePolicy", mock.Anything, certID, f.scope()).Return(policy, nil)

	cmd, buf := newCertRotationPolicyCmd(rotationPolicyGetCmd.RunE, []string{certID.String()})
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
	f.certSvc.AssertExpectations(t)
}

func TestCertRotationPolicyGetCmd_NoPolicy(t *testing.T) {
	f := newRotationPolicyFixture(t)
	certID := uuid.New()
	f.certSvc.On("GetCertificatePolicy", mock.Anything, certID, f.scope()).Return(nil, sql.ErrNoRows)

	cmd, buf := newCertRotationPolicyCmd(rotationPolicyGetCmd.RunE, []string{certID.String()})
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "No rotation policy set")
}

func TestCertRotationPolicyGetCmd_ServiceError(t *testing.T) {
	f := newRotationPolicyFixture(t)
	certID := uuid.New()
	f.certSvc.On("GetCertificatePolicy", mock.Anything, certID, f.scope()).Return(nil, fmt.Errorf("db error"))

	cmd, _ := newCertRotationPolicyCmd(rotationPolicyGetCmd.RunE, []string{certID.String()})
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to get rotation policy")
}

func TestCertRotationPolicyGetCmd_Denied(t *testing.T) {
	f := newRotationPolicyFixture(t)
	f.deny()
	certID := uuid.New()

	cmd, _ := newCertRotationPolicyCmd(rotationPolicyGetCmd.RunE, []string{certID.String()})
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "vault authorization failed")
	f.certSvc.AssertNotCalled(t, "GetCertificatePolicy", mock.Anything, mock.Anything, mock.Anything)
}

// ========== rotation-policy set ==========

func TestCertRotationPolicySetCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newCertRotationPolicyCmd(rotationPolicySetCmd.RunE, []string{uuid.New().String(), "--validity-months=12", "--subject=CN=example.com"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCertRotationPolicySetCmd_ForbiddenRole(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertRoleCtx(sc, model.RoleUser)
	cmd, _ := newCertRotationPolicyCmd(rotationPolicySetCmd.RunE, []string{uuid.New().String(), "--validity-months=12", "--subject=CN=example.com"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
}

func TestCertRotationPolicySetCmd_InvalidUUID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cmd, _ := newCertRotationPolicyCmd(rotationPolicySetCmd.RunE, []string{"not-a-uuid", "--validity-months=12", "--subject=CN=example.com"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid certificate ID")
}

func TestCertRotationPolicySetCmd_MissingRequiredFlags(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cmd, _ := newCertRotationPolicyCmd(rotationPolicySetCmd.RunE, []string{uuid.New().String()})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "are required")
}

func TestCertRotationPolicySetCmd_MissingSubjectOnly(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cmd, _ := newCertRotationPolicyCmd(rotationPolicySetCmd.RunE, []string{uuid.New().String(), "--validity-months=12"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "are required")
}

func TestCertRotationPolicySetCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cmd, _ := newCertRotationPolicyCmd(rotationPolicySetCmd.RunE, []string{uuid.New().String(), "--validity-months=12", "--subject=CN=example.com"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCertRotationPolicySetCmd_Success(t *testing.T) {
	f := newRotationPolicyFixture(t)
	certID := uuid.New()
	req := model.UpsertCertificatePolicyRequest{ValidityMonths: 12, Subject: "CN=example.com"}
	policy := &model.CertificatePolicy{CertificateID: certID, ValidityMonths: 12, Subject: "CN=example.com"}
	f.certSvc.On("UpsertCertificatePolicy", mock.Anything, certID, f.scope(), req).Return(policy, nil)

	cmd, buf := newCertRotationPolicyCmd(rotationPolicySetCmd.RunE, []string{certID.String(), "--validity-months=12", "--subject=CN=example.com"})
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "Rotation policy set for certificate")
	f.certSvc.AssertExpectations(t)
}

func TestCertRotationPolicySetCmd_ServiceError(t *testing.T) {
	f := newRotationPolicyFixture(t)
	certID := uuid.New()
	f.certSvc.On("UpsertCertificatePolicy", mock.Anything, certID, f.scope(), mock.Anything).Return(nil, fmt.Errorf("db error"))

	cmd, _ := newCertRotationPolicyCmd(rotationPolicySetCmd.RunE, []string{certID.String(), "--validity-months=12", "--subject=CN=example.com"})
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to set rotation policy")
}

func TestCertRotationPolicySetCmd_Denied(t *testing.T) {
	f := newRotationPolicyFixture(t)
	f.deny()
	certID := uuid.New()

	cmd, _ := newCertRotationPolicyCmd(rotationPolicySetCmd.RunE, []string{certID.String(), "--validity-months=12", "--subject=CN=example.com"})
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "vault authorization failed")
	f.certSvc.AssertNotCalled(t, "UpsertCertificatePolicy", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// ========== rotation-policy delete ==========

func TestCertRotationPolicyDeleteCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newCertRotationPolicyCmd(rotationPolicyDeleteCmd.RunE, []string{uuid.New().String()})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCertRotationPolicyDeleteCmd_ForbiddenRole(t *testing.T) {
	sc := &certsTestContainer{MockServiceContainer: &testutils.MockServiceContainer{}}
	ctx := buildCertRoleCtx(sc, model.RoleUser)
	cmd, _ := newCertRotationPolicyCmd(rotationPolicyDeleteCmd.RunE, []string{uuid.New().String()})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
}

func TestCertRotationPolicyDeleteCmd_InvalidUUID(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cmd, _ := newCertRotationPolicyCmd(rotationPolicyDeleteCmd.RunE, []string{"not-a-uuid"})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid certificate ID")
}

func TestCertRotationPolicyDeleteCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cmd, _ := newCertRotationPolicyCmd(rotationPolicyDeleteCmd.RunE, []string{uuid.New().String()})
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCertRotationPolicyDeleteCmd_Success(t *testing.T) {
	f := newRotationPolicyFixture(t)
	certID := uuid.New()
	f.certSvc.On("DeleteCertificatePolicy", mock.Anything, certID, f.scope()).Return(nil)

	cmd, buf := newCertRotationPolicyCmd(rotationPolicyDeleteCmd.RunE, []string{certID.String()})
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "deleted successfully")
	f.certSvc.AssertExpectations(t)
}

func TestCertRotationPolicyDeleteCmd_NotFound(t *testing.T) {
	f := newRotationPolicyFixture(t)
	certID := uuid.New()
	f.certSvc.On("DeleteCertificatePolicy", mock.Anything, certID, f.scope()).Return(sql.ErrNoRows)

	cmd, _ := newCertRotationPolicyCmd(rotationPolicyDeleteCmd.RunE, []string{certID.String()})
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "no rotation policy exists")
}

func TestCertRotationPolicyDeleteCmd_ServiceError(t *testing.T) {
	f := newRotationPolicyFixture(t)
	certID := uuid.New()
	f.certSvc.On("DeleteCertificatePolicy", mock.Anything, certID, f.scope()).Return(fmt.Errorf("db error"))

	cmd, _ := newCertRotationPolicyCmd(rotationPolicyDeleteCmd.RunE, []string{certID.String()})
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to delete rotation policy")
}

func TestCertRotationPolicyDeleteCmd_Denied(t *testing.T) {
	f := newRotationPolicyFixture(t)
	f.deny()
	certID := uuid.New()

	cmd, _ := newCertRotationPolicyCmd(rotationPolicyDeleteCmd.RunE, []string{certID.String()})
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "vault authorization failed")
	f.certSvc.AssertNotCalled(t, "DeleteCertificatePolicy", mock.Anything, mock.Anything, mock.Anything)
}

// ========== rotation-policy list ==========

func TestCertRotationPolicyListCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newCertRotationPolicyNoArgCmd(rotationPolicyListCmd.RunE)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCertRotationPolicyListCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cmd, _ := newCertRotationPolicyNoArgCmd(rotationPolicyListCmd.RunE)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCertRotationPolicyListCmd_Success(t *testing.T) {
	f := newRotationPolicyFixture(t)
	policies := []model.CertificatePolicyWithCertName{
		{
			CertificatePolicy: model.CertificatePolicy{
				CertificateID:    uuid.New(),
				ValidityMonths:   12,
				AutoRenew:        true,
				DaysBeforeExpiry: 30,
			},
			CertificateName: "example-cert",
		},
	}
	f.certSvc.On("ListCertificatePolicies", mock.Anything, f.scope()).Return(policies, nil)

	cmd, buf := newCertRotationPolicyNoArgCmd(rotationPolicyListCmd.RunE)
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "example-cert")
	f.certSvc.AssertExpectations(t)
}

func TestCertRotationPolicyListCmd_Empty(t *testing.T) {
	f := newRotationPolicyFixture(t)
	f.certSvc.On("ListCertificatePolicies", mock.Anything, f.scope()).Return([]model.CertificatePolicyWithCertName{}, nil)

	cmd, _ := newCertRotationPolicyNoArgCmd(rotationPolicyListCmd.RunE)
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
}

func TestCertRotationPolicyListCmd_ServiceError(t *testing.T) {
	f := newRotationPolicyFixture(t)
	f.certSvc.On("ListCertificatePolicies", mock.Anything, f.scope()).Return(nil, fmt.Errorf("db error"))

	cmd, _ := newCertRotationPolicyNoArgCmd(rotationPolicyListCmd.RunE)
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to list certificate policies")
}

func TestCertRotationPolicyListCmd_Denied(t *testing.T) {
	f := newRotationPolicyFixture(t)
	f.deny()

	cmd, _ := newCertRotationPolicyNoArgCmd(rotationPolicyListCmd.RunE)
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "vault authorization failed")
	f.certSvc.AssertNotCalled(t, "ListCertificatePolicies", mock.Anything, mock.Anything)
}

// ========== rotation-policy status ==========

func TestCertRotationPolicyStatusCmd_NoClaims(t *testing.T) {
	ctx := context.Background()
	cmd, _ := newCertRotationPolicyNoArgCmd(rotationPolicyStatusCmd.RunE)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized")
}

func TestCertRotationPolicyStatusCmd_NoServiceContainer(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newCertLogger())
	cmd, _ := newCertRotationPolicyNoArgCmd(rotationPolicyStatusCmd.RunE)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCertRotationPolicyStatusCmd_DueAndActive(t *testing.T) {
	f := newRotationPolicyFixture(t)
	expiresAt := time.Now().Add(10 * 24 * time.Hour)
	due := []model.Certificate{
		{ID: uuid.New(), Name: "expiring-cert", ExpiresAt: &expiresAt, AutoRenew: true, RenewalDays: 30},
	}
	active := []model.CertificatePolicyWithCertName{
		{CertificatePolicy: model.CertificatePolicy{AutoRenew: true, DaysBeforeExpiry: 30}, CertificateName: "policy-cert"},
		{CertificatePolicy: model.CertificatePolicy{AutoRenew: false, DaysBeforeExpiry: 60}, CertificateName: "inactive-cert"},
	}
	f.certSvc.On("ListCertificatesDueForRenewal", mock.Anything, f.scope()).Return(due, nil)
	f.certSvc.On("ListCertificatePolicies", mock.Anything, f.scope()).Return(active, nil)

	cmd, buf := newCertRotationPolicyNoArgCmd(rotationPolicyStatusCmd.RunE)
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "expiring-cert")
	assert.Contains(t, out, "policy-cert")
	assert.NotContains(t, out, "inactive-cert")
	f.certSvc.AssertExpectations(t)
}

func TestCertRotationPolicyStatusCmd_NoneDue(t *testing.T) {
	f := newRotationPolicyFixture(t)
	f.certSvc.On("ListCertificatesDueForRenewal", mock.Anything, f.scope()).Return([]model.Certificate{}, nil)
	f.certSvc.On("ListCertificatePolicies", mock.Anything, f.scope()).Return([]model.CertificatePolicyWithCertName{}, nil)

	cmd, buf := newCertRotationPolicyNoArgCmd(rotationPolicyStatusCmd.RunE)
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "No certificates are currently due for renewal")
}

func TestCertRotationPolicyStatusCmd_DueError(t *testing.T) {
	f := newRotationPolicyFixture(t)
	f.certSvc.On("ListCertificatesDueForRenewal", mock.Anything, f.scope()).Return(nil, fmt.Errorf("db error"))

	cmd, _ := newCertRotationPolicyNoArgCmd(rotationPolicyStatusCmd.RunE)
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to get due certificate renewals")
}

func TestCertRotationPolicyStatusCmd_PoliciesError(t *testing.T) {
	f := newRotationPolicyFixture(t)
	f.certSvc.On("ListCertificatesDueForRenewal", mock.Anything, f.scope()).Return([]model.Certificate{}, nil)
	f.certSvc.On("ListCertificatePolicies", mock.Anything, f.scope()).Return(nil, fmt.Errorf("db error"))

	cmd, _ := newCertRotationPolicyNoArgCmd(rotationPolicyStatusCmd.RunE)
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to list certificate policies")
}

func TestCertRotationPolicyStatusCmd_Denied(t *testing.T) {
	f := newRotationPolicyFixture(t)
	f.deny()

	cmd, _ := newCertRotationPolicyNoArgCmd(rotationPolicyStatusCmd.RunE)
	cmd.SetContext(f.ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "vault authorization failed")
	f.certSvc.AssertNotCalled(t, "ListCertificatesDueForRenewal", mock.Anything, mock.Anything)
	f.certSvc.AssertNotCalled(t, "ListCertificatePolicies", mock.Anything, mock.Anything)
}
