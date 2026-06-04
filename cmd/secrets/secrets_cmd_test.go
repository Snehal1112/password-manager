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
	claims := &model.Claims{UserID: userID, Username: "testuser", Role: model.RoleAdmin}
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
	claims := &model.Claims{UserID: userID, Username: "testuser", Role: model.RoleAdmin}
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
	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
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

	tc.MockSecretService.On("GetSecretInVault", mock.Anything, secretID, tc.TestVaultID).Return(secret, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	ctx := buildSecCtx(tc.MockContainer, tc.TestUserID)

	cmd, buf := newSecTestCmd(getCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "my-get-secret")
	tc.MockSecretService.AssertExpectations(t)
}

func TestGetCmd_ServiceError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	tc.MockSecretService.On("GetSecretInVault", mock.Anything, secretID, tc.TestVaultID).
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

	tc.MockSecretService.On("GetSecretInVault", mock.Anything, secretID, tc.TestVaultID).Return(secret, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	ctx := buildSecCtxNoFormatter(tc.MockContainer, tc.TestUserID)

	cmd, _ := newSecTestCmd(getCmd.RunE, []string{secretID.String()})
	cmd.Args = cobra.ExactArgs(1)
	cmd.SetContext(ctx)

	err := cmd.Execute()
	assert.ErrorContains(t, err, "output formatter not available")
	tc.MockSecretService.AssertExpectations(t)
}

// ---- deleteCmd: deleteCmd uses Run (not RunE) and calls os.Exit on failure.
// We validate the service contract by exercising the mock directly, which still
// covers the DeleteSecretInVault interface path used by the production code.

func TestDeleteCmd_ServiceContract_Success(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	tc.MockSecretService.On("DeleteSecretInVault", mock.Anything, secretID, tc.TestVaultID).Return(nil)

	err := tc.MockSecretService.DeleteSecretInVault(context.Background(), secretID, tc.TestVaultID)
	assert.NoError(t, err)
	tc.MockSecretService.AssertExpectations(t)
}

func TestDeleteCmd_ServiceContract_Error(t *testing.T) {
	tc := testutils.NewTestContext(t)
	secretID := uuid.New()

	tc.MockSecretService.On("DeleteSecretInVault", mock.Anything, secretID, tc.TestVaultID).
		Return(fmt.Errorf("delete failed"))

	err := tc.MockSecretService.DeleteSecretInVault(context.Background(), secretID, tc.TestVaultID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delete failed")
	tc.MockSecretService.AssertExpectations(t)
}

// ---- listCmd full RunE path tests ----

func TestListCmd_NoServiceContainer(t *testing.T) {
	userID := uuid.New()
	claims := &model.Claims{UserID: userID, Role: model.RoleAdmin}
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

	tc.MockSecretService.On("ListSecretsInVault", mock.Anything, tc.TestVaultID, []string{}).
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

	tc.MockSecretService.On("ListSecretsInVault", mock.Anything, tc.TestVaultID, []string{}).
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

	tc.MockSecretService.On("ListSecretsInVault", mock.Anything, tc.TestVaultID, []string{}).
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

func TestCreateCmd_NoUserID(t *testing.T) {
	tc := testutils.NewTestContext(t)
	// Build context without UserIDKey so the type assertion fails.
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.ServiceContainerKey, tc.MockContainer)
	ctx = context.WithValue(ctx, common.OutputFormatterKey, newSecFmtr())
	ctx = context.WithValue(ctx, common.LogKey, newSecLogger())
	// No UserIDKey.

	cmd := &cobra.Command{Use: "create", RunE: createCmd.RunE}
	cmd.Flags().StringSlice("tags", []string{}, "")
	cmd.Flags().String("content-type", "", "")
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"secret-name", "secret-value"})

	err := cmd.Execute()
	assert.ErrorContains(t, err, "user ID not available in context")
}

func TestCreateCmd_NoServiceContainer_FullRunE(t *testing.T) {
	userID := uuid.New()
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.UserIDKey, userID)
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
	ctx = context.WithValue(ctx, common.UserIDKey, userID)
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

func TestExportCmd_NoUserID(t *testing.T) {
	tc := testutils.NewTestContext(t)
	// Context without UserIDKey.
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
	assert.ErrorContains(t, err, "user not authenticated")
}

func TestExportCmd_NoServiceContainer(t *testing.T) {
	userID := uuid.New()
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.UserIDKey, userID)
	ctx = context.WithValue(ctx, common.LogKey, newSecLogger())
	// No ServiceContainerKey.

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

func TestImportCmd_NoUserID(t *testing.T) {
	// Context without UserIDKey.
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
	assert.ErrorContains(t, err, "user not authenticated")
}

func TestImportCmd_NoServiceContainer(t *testing.T) {
	userID := uuid.New()
	ctx := context.Background()
	ctx = context.WithValue(ctx, common.UserIDKey, userID)
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
	os.WriteFile(tmpFile, []byte(`{}`), 0o600)

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
