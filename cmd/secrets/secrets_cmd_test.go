package secrets

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	authzServices "rocketvault/internal/services/authorization"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// TestMain registers all Init functions exactly once, covering those
// registration statements, then runs all tests in this package.
func TestMain(m *testing.M) {
	parent := &cobra.Command{Use: "secrets"}
	InitSecretsCreate(parent)
	InitSecretsDelete(parent)
	InitSecretsGet(parent)
	InitSecretsList(parent)
	InitSecretsUpdate(parent)
	InitSecretsExport(parent)
	InitSecretsImport(parent)
	InitSecretsGenerate(parent)
	os.Exit(m.Run())
}

// ---- helpers ----

func newSecLogger() *logging.Logger {
	return &logging.Logger{Logger: logrus.New()}
}

func newSecFmtr() formatter.Formatter {
	f, _ := formatter.New(formatter.FormatTable)
	return f
}

// buildSecCtx builds a fully populated context for secrets tests.
func buildSecCtx(sc interface{}, userID uuid.UUID) context.Context {
	claims := &model.Claims{UserID: userID, Username: "testuser", Roles: []string{model.RoleAdmin}}
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newSecLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newSecFmtr())
	ctx = context.WithValue(ctx, common.UserIDKey, userID)
	return ctx
}

// buildSecCtxNoFormatter builds a context without an output formatter.
func buildSecCtxNoFormatter(sc interface{}, userID uuid.UUID) context.Context {
	claims := &model.Claims{UserID: userID, Username: "testuser", Roles: []string{model.RoleAdmin}}
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newSecLogger())
	ctx = context.WithValue(ctx, common.ServiceContainerKey, sc)
	ctx = context.WithValue(ctx, common.UserIDKey, userID)
	return ctx
}

func newSecTestCmd(runE func(*cobra.Command, []string) error, args []string) (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{Use: "test", RunE: runE}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	return cmd, &buf
}

// ---- getCmd tests ----

func TestGetCmd_NoServiceContainer(t *testing.T) {
	userID := uuid.New()
	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.LogKey, newSecLogger())
	ctx = context.WithValue(ctx, common.UserIDKey, userID)
	// No ServiceContainerKey.

	secretID := uuid.New()
	cmd, _ := newSecTestCmd(getCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestGetCmd_InvalidUUID(t *testing.T) {
	cmd, _ := newSecTestCmd(getCmd.RunE, []string{"not-a-uuid"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(context.Background())
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid secret ID")
}

func TestGetCmd_Success_WithFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()
	now := time.Now()
	secret := &model.Secret{
		ID:        secretID,
		Name:      "my-get-secret",
		Value:     "s3cr3t",
		Version:   1,
		Enabled:   true,
		CreatedAt: now,
		Tags:      []string{"env:prod"},
	}

	tc.MockSecretService.On("GetSecret", mock.Anything, secretID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(secret, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	// Assert the exact args reaching both authorization checks, not just
	// "some" values — a transposed action/op or swapped principal/vault must
	// fail this test, not pass it.
	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionSecretsGet).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceSecrets, model.OpGet, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles
	tc.MockContainer.AccessPolicyService = policies

	ctx := buildSecCtx(tc.MockContainer, tc.TestUserID)

	cmd, buf := newSecTestCmd(getCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "my-get-secret")
	tc.MockSecretService.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

func TestGetCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	tc.MockSecretService.On("GetSecret", mock.Anything, secretID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return(nil, fmt.Errorf("not found"))
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	ctx := buildSecCtx(tc.MockContainer, tc.TestUserID)

	cmd, _ := newSecTestCmd(getCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to retrieve secret")
	tc.MockSecretService.AssertExpectations(t)
}

func TestGetCmd_NoFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()
	now := time.Now()
	secret := &model.Secret{
		ID:        secretID,
		Name:      "fmt-missing",
		Value:     "val",
		Version:   1,
		Enabled:   true,
		CreatedAt: now,
	}

	tc.MockSecretService.On("GetSecret", mock.Anything, secretID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(secret, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	ctx := buildSecCtxNoFormatter(tc.MockContainer, tc.TestUserID)

	cmd, _ := newSecTestCmd(getCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	tc.MockSecretService.AssertExpectations(t)
}

func TestGetCmd_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	secretID := uuid.New()
	ctx := buildSecCtx(tc.MockContainer, tc.TestUserID)

	cmd, _ := newSecTestCmd(getCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	tc.MockSecretService.AssertNotCalled(t, "GetSecret", mock.Anything, mock.Anything, mock.Anything)
}

// ---- deleteCmd ----

func TestDeleteCmd_InvalidUUID(t *testing.T) {
	cmd, _ := newSecTestCmd(deleteCmd.RunE, []string{"not-a-uuid"})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(context.Background())
	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid secret ID")
}

func TestDeleteCmd_NoServiceContainer(t *testing.T) {
	secretID := uuid.New()
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}})
	ctx = context.WithValue(ctx, common.LogKey, newSecLogger())
	// No ServiceContainerKey.

	cmd, _ := newSecTestCmd(deleteCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestDeleteCmd_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	tc.MockSecretService.On("DeleteSecret", mock.Anything, secretID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	// Assert the exact args reaching both authorization checks, not just
	// "some" values — a transposed action/op or swapped principal/vault must
	// fail this test, not pass it.
	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionSecretsDelete).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceSecrets, model.OpDelete, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles
	tc.MockContainer.AccessPolicyService = policies

	cmd, _ := newSecTestCmd(deleteCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(tc.Ctx)
	err := cmd.Execute()
	assert.NoError(t, err)
	tc.MockSecretService.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

func TestDeleteCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	tc.MockSecretService.On("DeleteSecret", mock.Anything, secretID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return(fmt.Errorf("delete failed"))
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	cmd, _ := newSecTestCmd(deleteCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(tc.Ctx)
	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to delete secret")
	tc.MockSecretService.AssertExpectations(t)
}

// TestDeleteCmd_ServiceContract_Success and TestDeleteCmd_ServiceContract_Error
// pin the DeleteSecret mock contract used above, independent of the command wiring.

func TestDeleteCmd_ServiceContract_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	tc.MockSecretService.On("DeleteSecret", mock.Anything, secretID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).Return(nil)

	err := tc.MockSecretService.DeleteSecret(context.Background(), secretID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID))
	assert.NoError(t, err)
	tc.MockSecretService.AssertExpectations(t)
}

func TestDeleteCmd_ServiceContract_Error(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	tc.MockSecretService.On("DeleteSecret", mock.Anything, secretID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID)).
		Return(fmt.Errorf("delete failed"))

	err := tc.MockSecretService.DeleteSecret(context.Background(), secretID, model.NewVaultScope(tc.TestVaultID, tc.TestUserID))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delete failed")
	tc.MockSecretService.AssertExpectations(t)
}

func TestDeleteCmd_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	secretID := uuid.New()

	cmd, _ := newSecTestCmd(deleteCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
	tc.MockSecretService.AssertNotCalled(t, "DeleteSecret", mock.Anything, mock.Anything, mock.Anything)
}

// ---- listCmd full RunE path tests ----

func TestListCmd_NoServiceContainer(t *testing.T) {
	userID := uuid.New()
	claims := &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}}
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, claims)
	ctx = context.WithValue(ctx, common.UserIDKey, userID)
	// No ServiceContainerKey.

	cmd := &cobra.Command{Use: "list", RunE: listCmd.RunE}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestListCmd_Success_WithFormatter(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secrets := []model.Secret{
		{ID: uuid.New(), Name: "secret-alpha", Version: 1, Enabled: true, CreatedAt: time.Now()},
		{ID: uuid.New(), Name: "secret-beta", Version: 2, Enabled: false, CreatedAt: time.Now()},
	}

	tc.MockSecretService.On("ListSecrets", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), []string{}).
		Return(secrets, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	ctx := buildSecCtx(tc.MockContainer, tc.TestUserID)

	cmd := &cobra.Command{Use: "list", RunE: listCmd.RunE}
	cmd.Flags().StringSlice("tags", []string{}, "")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.NoError(t, err)
	out := buf.String()
	assert.Contains(t, out, "secret-alpha")
	assert.Contains(t, out, "secret-beta")
	tc.MockSecretService.AssertExpectations(t)
}

func TestListCmd_ServiceError_FullRunE(t *testing.T) {
	tc := testutils.NewTestContext(t)

	tc.MockSecretService.On("ListSecrets", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), []string{}).
		Return(nil, fmt.Errorf("database error"))
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	ctx := buildSecCtx(tc.MockContainer, tc.TestUserID)

	cmd := &cobra.Command{Use: "list", RunE: listCmd.RunE}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to list secrets")
	tc.MockSecretService.AssertExpectations(t)
}

func TestListCmd_NoFormatter_FullRunE(t *testing.T) {
	tc := testutils.NewTestContext(t)

	tc.MockSecretService.On("ListSecrets", mock.Anything, model.NewVaultScope(tc.TestVaultID, tc.TestUserID), []string{}).
		Return([]model.Secret{}, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	ctx := buildSecCtxNoFormatter(tc.MockContainer, tc.TestUserID)

	cmd := &cobra.Command{Use: "list", RunE: listCmd.RunE}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
}

// ---- formatOptionalTime tests ----

func TestFormatOptionalTime_Nil(t *testing.T) {
	result := formatOptionalTime(nil)
	assert.Equal(t, "", result)
}

func TestFormatOptionalTime_NonNil(t *testing.T) {
	now := time.Now()
	result := formatOptionalTime(&now)
	assert.Equal(t, now.Format(time.RFC3339), result)
}

// ---- createCmd additional path coverage ----

func TestCreateCmd_NoClaims(t *testing.T) {
	tc := testutils.NewTestContext(t)
	// Build context without ClaimsKey so the type assertion fails.
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ServiceContainerKey, tc.MockContainer)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newSecFmtr())
	ctx = context.WithValue(ctx, common.LogKey, newSecLogger())
	// No ClaimsKey.

	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.Flags().String("content-type", "", "")
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"secret-name", "secret-value"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized: missing authentication claims")
}

func TestCreateCmd_ForbiddenRole(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleUser}})
	ctx = context.WithValue(ctx, common.LogKey, newSecLogger())

	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.Flags().String("content-type", "", "")
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"secret-name", "secret-value"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "forbidden")
}

func TestCreateCmd_NoServiceContainer_FullRunE(t *testing.T) {
	userID := uuid.New()
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}})
	ctx = context.WithValue(ctx, common.LogKey, newSecLogger())
	// No ServiceContainerKey.

	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.Flags().String("content-type", "", "")
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"secret-name", "secret-value"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestCreateCmd_ServiceError_FullRunE(t *testing.T) {
	tc := testutils.NewTestContext(t)

	tc.MockSecretService.On("CreateSecret", mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("db write failed"))
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	ctx := buildSecCtx(tc.MockContainer, tc.TestUserID)

	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.Flags().String("content-type", "", "")
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"secret-name", "secret-value"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to create secret")
	tc.MockSecretService.AssertExpectations(t)
}

func TestCreateCmd_NoFormatter_FullRunE(t *testing.T) {
	tc := testutils.NewTestContext(t)
	now := time.Now()
	secret := &model.Secret{
		ID:        uuid.New(),
		Name:      "no-fmt-secret",
		Version:   1,
		Enabled:   true,
		CreatedAt: now,
	}

	tc.MockSecretService.On("CreateSecret", mock.Anything, mock.Anything).Return(secret, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	ctx := buildSecCtxNoFormatter(tc.MockContainer, tc.TestUserID)

	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.Flags().String("content-type", "", "")
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"secret-name", "secret-value"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	tc.MockSecretService.AssertExpectations(t)
}

// ---- updateCmd additional path coverage ----

func TestUpdateCmd_NoServiceContainer_FullRunE(t *testing.T) {
	userID := uuid.New()
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}})
	ctx = context.WithValue(ctx, common.LogKey, newSecLogger())
	// No ServiceContainerKey.

	secretID := uuid.New()
	cmd := &cobra.Command{
		Use:  "update [id] [value]",
		Args: cobra.ExactArgs(2),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.Flags().String("content-type", "", "")
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{secretID.String(), "newvalue"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestUpdateCmd_InvalidID_FullRunE(t *testing.T) {
	userID := uuid.New()
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.UserIDKey, userID)
	ctx = context.WithValue(ctx, common.LogKey, newSecLogger())

	cmd := &cobra.Command{
		Use:  "update [id] [value]",
		Args: cobra.ExactArgs(2),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.Flags().String("content-type", "", "")
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"not-a-uuid", "newvalue"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "invalid secret ID")
}

func TestUpdateCmd_WithContentType_FullRunE(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	tc.MockSecretService.On("UpdateSecret", mock.Anything, mock.MatchedBy(func(r secretServices.UpdateSecretRequest) bool {
		return r.SecretID == secretID &&
			r.ContentType != nil && *r.ContentType == "application/json"
	})).Return(nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	ctx := buildSecCtx(tc.MockContainer, tc.TestUserID)

	cmd := &cobra.Command{
		Use:  "update [id] [value]",
		Args: cobra.ExactArgs(2),
		RunE: updateCmd.RunE,
	}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.Flags().String("content-type", "", "")
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{secretID.String(), "newvalue", "--content-type=application/json"})

	err := cmd.Execute()
	require.NoError(t, err)
	tc.MockSecretService.AssertExpectations(t)
}

// ---- exportCmd additional coverage ----

func TestExportCmd_UnsupportedFormat(t *testing.T) {
	tc := testutils.NewTestContext(t)
	ctx := buildSecCtx(tc.MockContainer, tc.TestUserID)

	prevFormat := exportFormat
	exportFormat = "xml"
	defer func() { exportFormat = prevFormat }()

	tmpFile := t.TempDir() + "/out.xml"
	prevFile := exportFile
	exportFile = tmpFile
	defer func() { exportFile = prevFile }()

	cmd := &cobra.Command{Use: "export", RunE: secretsExportCmd.RunE}
	cmd.Flags().StringVarP(&exportFormat, "format", "f", "xml", "")
	cmd.Flags().StringVarP(&exportFile, "file", "o", tmpFile, "")
	cmd.Flags().BoolVarP(&exportEncrypt, "encrypt", "e", false, "")
	cmd.Flags().StringSliceVarP(&exportTags, "tags", "t", []string{}, "")
	cmd.Flags().StringSliceVar(&exportFilterTags, "filter-tags", []string{}, "")
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "unsupported format")
}

func TestExportCmd_NoClaims(t *testing.T) {
	tc := testutils.NewTestContext(t)
	// Context without ClaimsKey.
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ServiceContainerKey, tc.MockContainer)
	ctx = context.WithValue(ctx, common.LogKey, newSecLogger())

	prevFormat := exportFormat
	exportFormat = "json"
	defer func() { exportFormat = prevFormat }()
	prevFile := exportFile
	exportFile = t.TempDir() + "/export.json"
	defer func() { exportFile = prevFile }()

	cmd := &cobra.Command{Use: "export", RunE: secretsExportCmd.RunE}
	cmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&exportFile, "file", "o", exportFile, "")
	cmd.Flags().BoolVarP(&exportEncrypt, "encrypt", "e", false, "")
	cmd.Flags().StringSliceVarP(&exportTags, "tags", "t", []string{}, "")
	cmd.Flags().StringSliceVar(&exportFilterTags, "filter-tags", []string{}, "")
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized: missing authentication claims")
}

func TestExportCmd_NoServiceContainer(t *testing.T) {
	userID := uuid.New()
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}})
	ctx = context.WithValue(ctx, common.LogKey, newSecLogger())
	// No ServiceContainerKey.

	prevFormat := exportFormat
	exportFormat = "json"
	defer func() { exportFormat = prevFormat }()
	prevFile := exportFile
	exportFile = t.TempDir() + "/export.json"
	defer func() { exportFile = prevFile }()
	exportEncrypt = false
	exportPassphraseFile = ""

	cmd := &cobra.Command{Use: "export", RunE: secretsExportCmd.RunE}
	cmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&exportFile, "file", "o", exportFile, "")
	cmd.Flags().BoolVarP(&exportEncrypt, "encrypt", "e", false, "")
	cmd.Flags().StringSliceVarP(&exportTags, "tags", "t", []string{}, "")
	cmd.Flags().StringSliceVar(&exportFilterTags, "filter-tags", []string{}, "")
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestExportCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockSecretService.On("ExportSecrets", mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("export backend error"))
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	ctx := buildSecCtx(tc.MockContainer, tc.TestUserID)

	prevFormat := exportFormat
	exportFormat = "json"
	defer func() { exportFormat = prevFormat }()
	prevFile := exportFile
	exportFile = t.TempDir() + "/export.json"
	defer func() { exportFile = prevFile }()
	exportTags = []string{}
	exportFilterTags = []string{}
	exportEncrypt = false
	exportPassphraseFile = ""

	cmd := &cobra.Command{Use: "export", RunE: secretsExportCmd.RunE}
	cmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&exportFile, "file", "o", exportFile, "")
	cmd.Flags().BoolVarP(&exportEncrypt, "encrypt", "e", false, "")
	cmd.Flags().StringSliceVarP(&exportTags, "tags", "t", []string{}, "")
	cmd.Flags().StringSliceVar(&exportFilterTags, "filter-tags", []string{}, "")
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to export secrets")
	tc.MockSecretService.AssertExpectations(t)
}

// ---- importCmd additional coverage ----

func TestImportCmd_NoClaims(t *testing.T) {
	// Context without ClaimsKey.
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.LogKey, newSecLogger())

	prevFormat := importFormat
	importFormat = "json"
	defer func() { importFormat = prevFormat }()
	prevFile := importFile
	importFile = t.TempDir() + "/import.json"
	defer func() { importFile = prevFile }()

	cmd := &cobra.Command{Use: "import", RunE: secretsImportCmd.RunE}
	cmd.Flags().StringVarP(&importFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&importFile, "file", "i", importFile, "")
	cmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", false, "")
	cmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "")
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "unauthorized: missing authentication claims")
}

func TestImportCmd_NoServiceContainer(t *testing.T) {
	userID := uuid.New()
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ClaimsKey, &model.Claims{UserID: userID, Roles: []string{model.RoleAdmin}})
	ctx = context.WithValue(ctx, common.LogKey, newSecLogger())
	// No ServiceContainerKey.

	prevFormat := importFormat
	importFormat = "json"
	defer func() { importFormat = prevFormat }()
	prevFile := importFile
	importFile = t.TempDir() + "/import.json"
	defer func() { importFile = prevFile }()

	cmd := &cobra.Command{Use: "import", RunE: secretsImportCmd.RunE}
	cmd.Flags().StringVarP(&importFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&importFile, "file", "i", importFile, "")
	cmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", false, "")
	cmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "")
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "service container not available")
}

func TestImportCmd_UnsupportedFormat(t *testing.T) {
	tc := testutils.NewTestContext(t)
	ctx := buildSecCtx(tc.MockContainer, tc.TestUserID)

	prevFormat := importFormat
	importFormat = "toml"
	defer func() { importFormat = prevFormat }()
	prevFile := importFile
	importFile = t.TempDir() + "/import.toml"
	defer func() { importFile = prevFile }()

	cmd := &cobra.Command{Use: "import", RunE: secretsImportCmd.RunE}
	cmd.Flags().StringVarP(&importFormat, "format", "f", "toml", "")
	cmd.Flags().StringVarP(&importFile, "file", "i", importFile, "")
	cmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", false, "")
	cmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "")
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "unsupported format")
}

func TestImportCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)

	tc.MockSecretService.On("ImportSecrets", mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("import backend error"))
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	ctx := buildSecCtx(tc.MockContainer, tc.TestUserID)

	tmpFile := t.TempDir() + "/import.json"
	os.WriteFile(tmpFile, []byte(`{}`), 0o600) //nolint:errcheck,gosec

	prevFormat := importFormat
	importFormat = "json"
	defer func() { importFormat = prevFormat }()
	prevFile := importFile
	importFile = tmpFile
	defer func() { importFile = prevFile }()
	importOverwrite = false

	cmd := &cobra.Command{Use: "import", RunE: secretsImportCmd.RunE}
	cmd.Flags().StringVarP(&importFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&importFile, "file", "i", tmpFile, "")
	cmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", false, "")
	cmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "")
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "failed to import secrets")
	tc.MockSecretService.AssertExpectations(t)
}
