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

package keys

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/common"
	"rocketvault/model"
)

func newRotationPolicyTestCmd(runE func(*cobra.Command, []string) error, args []string) *cobra.Command {
	cmd := &cobra.Command{Use: "test", Args: cobra.ExactArgs(1), RunE: runE}
	cmd.Flags().Int("rotate-after-days", 0, "")
	cmd.Flags().Int("notify-before-expiry-days", 0, "")
	cmd.Flags().Int("expiry-days", 0, "")
	cmd.Flags().Bool("enabled", false, "")
	cmd.SetArgs(args)
	return cmd
}

// ========== rotation-policy get ==========

func TestRotationPolicyGetCmd_Success(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	policy := &model.KeyRotationPolicy{
		KeyID:           keyID,
		RotateAfterDays: 90,
		Enabled:         true,
		NextRotationAt:  time.Now().Add(90 * 24 * time.Hour),
	}
	keySvc.On("GetKeyRotationPolicy", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(policy, nil)

	ctx := buildAdminClaimsCtx(userID, sc)
	cmd := newRotationPolicyTestCmd(rotationPolicyGetCmd.RunE, []string{keyID.String()})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
}

func TestRotationPolicyGetCmd_NoPolicy(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keySvc.On("GetKeyRotationPolicy", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(nil, sql.ErrNoRows)

	ctx := buildAdminClaimsCtx(userID, sc)
	cmd := newRotationPolicyTestCmd(rotationPolicyGetCmd.RunE, []string{keyID.String()})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
}

func TestRotationPolicyGetCmd_Denied(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc := newDeniedContainer(keySvc, nil)

	ctx := buildAdminClaimsCtx(userID, sc)
	cmd := newRotationPolicyTestCmd(rotationPolicyGetCmd.RunE, []string{keyID.String()})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "vault authorization failed")
	keySvc.AssertNotCalled(t, "GetKeyRotationPolicy", mock.Anything, mock.Anything, mock.Anything)
}

func TestRotationPolicyGetCmd_InvalidUUID(t *testing.T) {
	ctx := buildAdminClaimsCtx(uuid.New(), nil)
	cmd := newRotationPolicyTestCmd(rotationPolicyGetCmd.RunE, []string{"not-a-uuid"})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid key ID")
}

// ========== rotation-policy set ==========

func TestRotationPolicySetCmd_Success(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	req := model.UpsertKeyRotationPolicyRequest{RotateAfterDays: 90, Enabled: true}
	policy := &model.KeyRotationPolicy{KeyID: keyID, RotateAfterDays: 90, Enabled: true, NextRotationAt: time.Now().Add(90 * 24 * time.Hour)}
	keySvc.On("UpsertKeyRotationPolicy", mock.Anything, keyID, model.NewVaultScope(vaultID, userID), req).Return(policy, nil)

	ctx := buildAdminClaimsCtx(userID, sc)
	cmd := newRotationPolicyTestCmd(rotationPolicySetCmd.RunE, []string{keyID.String(), "--rotate-after-days=90", "--enabled=true"})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
}

func TestRotationPolicySetCmd_MissingRequiredFlags(t *testing.T) {
	ctx := buildAdminClaimsCtx(uuid.New(), nil)
	cmd := newRotationPolicyTestCmd(rotationPolicySetCmd.RunE, []string{uuid.New().String()})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "are required")
}

func TestRotationPolicySetCmd_ValidationFailure(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	sc, _ := newAllowedContainer(keySvc, nil)

	ctx := buildAdminClaimsCtx(uuid.New(), sc)
	cmd := newRotationPolicyTestCmd(rotationPolicySetCmd.RunE, []string{uuid.New().String(), "--rotate-after-days=3", "--enabled=true"})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid rotation policy")
	keySvc.AssertNotCalled(t, "UpsertKeyRotationPolicy", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestRotationPolicySetCmd_ForbiddenRole(t *testing.T) {
	userID := uuid.New()
	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleUser}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())

	cmd := newRotationPolicyTestCmd(rotationPolicySetCmd.RunE, []string{uuid.New().String(), "--rotate-after-days=90", "--enabled=true"})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
}

func TestRotationPolicySetCmd_Denied(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc := newDeniedContainer(keySvc, nil)

	ctx := buildAdminClaimsCtx(userID, sc)
	cmd := newRotationPolicyTestCmd(rotationPolicySetCmd.RunE, []string{uuid.New().String(), "--rotate-after-days=90", "--enabled=true"})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "vault authorization failed")
	keySvc.AssertNotCalled(t, "UpsertKeyRotationPolicy", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// ========== rotation-policy delete ==========

func TestRotationPolicyDeleteCmd_Success(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keySvc.On("DeleteKeyRotationPolicy", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(nil)

	ctx := buildAdminClaimsCtx(userID, sc)
	cmd := newRotationPolicyTestCmd(rotationPolicyDeleteCmd.RunE, []string{keyID.String()})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
}

func TestRotationPolicyDeleteCmd_NotFound(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keySvc.On("DeleteKeyRotationPolicy", mock.Anything, keyID, model.NewVaultScope(vaultID, userID)).Return(sql.ErrNoRows)

	ctx := buildAdminClaimsCtx(userID, sc)
	cmd := newRotationPolicyTestCmd(rotationPolicyDeleteCmd.RunE, []string{keyID.String()})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "no rotation policy exists")
}

func TestRotationPolicyDeleteCmd_ForbiddenRole(t *testing.T) {
	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleUser}}
	ctx := context.WithValue(context.Background(), common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())

	cmd := newRotationPolicyTestCmd(rotationPolicyDeleteCmd.RunE, []string{uuid.New().String()})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
}

func TestRotationPolicyDeleteCmd_Denied(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc := newDeniedContainer(keySvc, nil)

	ctx := buildAdminClaimsCtx(userID, sc)
	cmd := newRotationPolicyTestCmd(rotationPolicyDeleteCmd.RunE, []string{uuid.New().String()})
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "vault authorization failed")
	keySvc.AssertNotCalled(t, "DeleteKeyRotationPolicy", mock.Anything, mock.Anything, mock.Anything)
}

// ========== rotation-policy list ==========

// newRotationPolicyNoArgTestCmd builds a no-arg cobra command for the list
// and status subcommands, mirroring newRotationPolicyTestCmd but without the
// single-argument requirement get/set/delete need.
func newRotationPolicyNoArgTestCmd(runE func(*cobra.Command, []string) error) *cobra.Command {
	cmd := &cobra.Command{Use: "test", Args: cobra.NoArgs, RunE: runE}
	cmd.SetArgs([]string{})
	return cmd
}

func TestRotationPolicyListCmd_Success(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	policies := []model.KeyRotationPolicyWithKeyName{
		{
			KeyRotationPolicy: model.KeyRotationPolicy{
				KeyID:           keyID,
				RotateAfterDays: 90,
				Enabled:         true,
				NextRotationAt:  time.Now().Add(90 * 24 * time.Hour),
			},
			KeyName: "my-key",
		},
	}
	keySvc.On("ListKeyRotationPolicies", mock.Anything, model.NewVaultScope(vaultID, userID)).Return(policies, nil)

	ctx := buildAdminClaimsCtx(userID, sc)
	cmd := newRotationPolicyNoArgTestCmd(rotationPolicyListCmd.RunE)
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)
}

func TestRotationPolicyListCmd_Empty(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	keySvc.On("ListKeyRotationPolicies", mock.Anything, model.NewVaultScope(vaultID, userID)).Return([]model.KeyRotationPolicyWithKeyName{}, nil)

	ctx := buildAdminClaimsCtx(userID, sc)
	cmd := newRotationPolicyNoArgTestCmd(rotationPolicyListCmd.RunE)
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
}

func TestRotationPolicyListCmd_Denied(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc := newDeniedContainer(keySvc, nil)

	ctx := buildAdminClaimsCtx(userID, sc)
	cmd := newRotationPolicyNoArgTestCmd(rotationPolicyListCmd.RunE)
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "vault authorization failed")
	keySvc.AssertNotCalled(t, "ListKeyRotationPolicies", mock.Anything, mock.Anything)
}

// ========== rotation-policy status ==========

func TestRotationPolicyStatusCmd_DueAndActive(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	keyID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	scope := model.NewVaultScope(vaultID, userID)

	due := []model.KeyRotationPolicy{
		{KeyID: keyID, RotateAfterDays: 90, Enabled: true, NextRotationAt: time.Now().Add(-time.Hour)},
	}
	active := []model.KeyRotationPolicyWithKeyName{
		{
			KeyRotationPolicy: model.KeyRotationPolicy{KeyID: keyID, RotateAfterDays: 90, Enabled: true},
			KeyName:           "my-key",
		},
	}
	keySvc.On("ListDueKeyRotationPolicies", mock.Anything, scope).Return(due, nil)
	keySvc.On("ListKeyRotationPolicies", mock.Anything, scope).Return(active, nil)

	ctx := buildAdminClaimsCtx(userID, sc)
	cmd := newRotationPolicyNoArgTestCmd(rotationPolicyStatusCmd.RunE)
	cmd.SetContext(ctx)

	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
	keySvc.AssertExpectations(t)

	output := out.String()
	assert.Contains(t, output, "Keys due for rotation:")
	assert.Contains(t, output, "Key "+keyID.String()[:8]+"...")
	assert.Contains(t, output, "Active rotation policies:")
	assert.Contains(t, output, "my-key: every 90 days")
}

func TestRotationPolicyStatusCmd_NoneDue(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc, vaultID := newAllowedContainer(keySvc, nil)
	scope := model.NewVaultScope(vaultID, userID)

	keySvc.On("ListDueKeyRotationPolicies", mock.Anything, scope).Return([]model.KeyRotationPolicy{}, nil)
	keySvc.On("ListKeyRotationPolicies", mock.Anything, scope).Return([]model.KeyRotationPolicyWithKeyName{}, nil)

	ctx := buildAdminClaimsCtx(userID, sc)
	cmd := newRotationPolicyNoArgTestCmd(rotationPolicyStatusCmd.RunE)
	cmd.SetContext(ctx)

	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	assert.NoError(t, err)

	output := out.String()
	assert.Contains(t, output, "No keys are currently due for rotation.")
}

func TestRotationPolicyStatusCmd_Denied(t *testing.T) {
	keySvc := &keyCmdKeyService{}
	userID := uuid.New()
	sc := newDeniedContainer(keySvc, nil)

	ctx := buildAdminClaimsCtx(userID, sc)
	cmd := newRotationPolicyNoArgTestCmd(rotationPolicyStatusCmd.RunE)
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "vault authorization failed")
	keySvc.AssertNotCalled(t, "ListDueKeyRotationPolicies", mock.Anything, mock.Anything)
	keySvc.AssertNotCalled(t, "ListKeyRotationPolicies", mock.Anything, mock.Anything)
}

// buildAdminClaimsCtx builds a context with admin claims, a logger, the
// given service container and a table formatter, keyed to userID so mock
// expectations set up against it line up.
func buildAdminClaimsCtx(userID uuid.UUID, sc any) context.Context {
	claims := &model.Claims{UserID: userID, Username: "admin", Roles: []string{model.RoleAdmin}}
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newTestFmtr())
	return ctx
}
