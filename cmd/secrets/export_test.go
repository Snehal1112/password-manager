package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	authzServices "rocketvault/internal/services/authorization"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

func TestExportCommand_CallsServiceExport(t *testing.T) {
	tc := testutils.NewTestContext(t)

	// The request must carry a vault scope built from the real authenticated
	// user, matching api/secrets.go's exportSecrets handler on the
	// /vaults/{name}/secrets/... route (scopeFromRequest returns a vault
	// scope there): any vault member holding a role that grants
	// ActionSecretsGet can export the vault's secrets, not just their own. A
	// zero Scope has kind ScopeInvalid and every repository query rejects
	// it, so this assertion also catches a "Scope never set" regression.
	wantScope := model.NewVaultScope(tc.TestVaultID, tc.TestUserID)
	tc.MockSecretService.On("ExportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ExportSecretsRequest) bool {
		return r.Format == "json" && r.Scope == wantScope
	})).Return([]byte(`{"secrets":[]}`), nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	// Assert the exact args reaching both authorization checks, not just
	// "some" values — a transposed action/op or swapped principal/vault must
	// fail this test, not pass it. Note export resolves to OpCreate, not
	// OpGet, despite its DataAction being ActionSecretsGet: resolvePolicy
	// treats every POST route without one of five special suffixes as
	// OpCreate (see the design doc's "resolvePolicy quirk" note).
	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionSecretsGet).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceSecrets, model.OpCreate, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles
	tc.MockContainer.AccessPolicyService = policies

	tmpFile := t.TempDir() + "/export.json"

	// Reset package-level vars before test.
	exportFormat = "json"
	exportFile = tmpFile
	exportEncrypt = false
	exportPassphraseFile = ""
	exportTags = []string{}
	exportFilterTags = []string{}

	cmd := &cobra.Command{Use: "export", RunE: secretsExportCmd.RunE}
	cmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&exportFile, "file", "o", tmpFile, "")
	cmd.Flags().BoolVarP(&exportEncrypt, "encrypt", "e", false, "")
	cmd.Flags().StringSliceVarP(&exportTags, "tags", "t", []string{}, "")
	cmd.Flags().StringSliceVar(&exportFilterTags, "filter-tags", []string{}, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	tc.MockSecretService.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

func TestExportCommand_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	tmpFile := t.TempDir() + "/export.json"
	exportFormat = "json"
	exportFile = tmpFile
	exportEncrypt = false
	exportPassphraseFile = ""
	exportTags = []string{}
	exportFilterTags = []string{}

	cmd := &cobra.Command{Use: "export", RunE: secretsExportCmd.RunE}
	cmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&exportFile, "file", "o", tmpFile, "")
	cmd.Flags().BoolVarP(&exportEncrypt, "encrypt", "e", false, "")
	cmd.Flags().StringSliceVarP(&exportTags, "tags", "t", []string{}, "")
	cmd.Flags().StringSliceVar(&exportFilterTags, "filter-tags", []string{}, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
	tc.MockSecretService.AssertNotCalled(t, "ExportSecrets", mock.Anything, mock.Anything)
}

// TestExportCommand_Forbidden_NeverPromptsForPassphrase guards the ordering
// itself, not just its outcome: with encryption on and no passphrase source
// available, a denied authorization check must still fail with the
// authorization error, never the passphrase error. If a future edit moved
// passphrase resolution above the vaultcli.RequireDataAction check, this
// test would start seeing the "no passphrase" error instead and fail, even
// though every other test in this file would still pass.
func TestExportCommand_Forbidden_NeverPromptsForPassphrase(t *testing.T) {
	tc := testutils.NewTestContext(t)

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	// go test runs with stdin detached, so if passphrase resolution were
	// ever reached it would fail with ErrNoPassphraseAvailable rather than
	// hanging on a prompt.
	t.Setenv("ROCKETVAULT_EXPORT_PASSPHRASE", "")

	tmpFile := t.TempDir() + "/export.json"
	exportFormat = "json"
	exportFile = tmpFile
	exportEncrypt = true
	exportPassphraseFile = ""
	exportTags = []string{}
	exportFilterTags = []string{}

	cmd := newExportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
	assert.NotContains(t, err.Error(), "no passphrase")
	assert.NoFileExists(t, tmpFile)
	tc.MockSecretService.AssertNotCalled(t, "ExportSecrets", mock.Anything, mock.Anything)
}

// newExportTestCmd builds a standalone command sharing the real export RunE, so
// the flag set matches what InitSecretsExport registers.
func newExportTestCmd(file string) *cobra.Command {
	cmd := &cobra.Command{Use: "export", RunE: secretsExportCmd.RunE}
	cmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&exportFile, "file", "o", file, "")
	cmd.Flags().BoolVarP(&exportEncrypt, "encrypt", "e", exportEncrypt, "")
	cmd.Flags().StringVar(&exportPassphraseFile, "passphrase-file", exportPassphraseFile, "")
	cmd.Flags().StringSliceVarP(&exportTags, "tags", "t", []string{}, "")
	cmd.Flags().StringSliceVar(&exportFilterTags, "filter-tags", []string{}, "")
	return cmd
}

func TestExportCommand_EncryptWithNoPassphraseSource_FailsAndWritesNoFile(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService).Maybe()

	// go test runs with stdin detached, so ResolvePassphrase takes its
	// non-terminal branch and returns ErrNoPassphraseAvailable.
	t.Setenv("ROCKETVAULT_EXPORT_PASSPHRASE", "")

	tmpFile := filepath.Join(t.TempDir(), "export.json")
	exportFormat = "json"
	exportFile = tmpFile
	exportEncrypt = true
	exportPassphraseFile = ""
	exportTags = []string{}
	exportFilterTags = []string{}

	cmd := newExportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no passphrase")
	assert.NoFileExists(t, tmpFile, "a failed encrypted export must leave nothing on disk")
	tc.MockSecretService.AssertNotCalled(t, "ExportSecrets", mock.Anything, mock.Anything)
}

func TestExportCommand_PassphraseFileIsPlumbedIntoRequest(t *testing.T) {
	tc := testutils.NewTestContext(t)

	dir := t.TempDir()
	passFile := filepath.Join(dir, "pass.txt")
	require.NoError(t, os.WriteFile(passFile, []byte("s3cret\n"), 0o600))
	tmpFile := filepath.Join(dir, "export.json")

	tc.MockSecretService.On("ExportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ExportSecretsRequest) bool {
		return r.Encrypt && r.Passphrase == "s3cret"
	})).Return([]byte(`{"rocketvault_export":1}`), nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	exportFormat = "json"
	exportFile = tmpFile
	exportEncrypt = true
	exportPassphraseFile = passFile
	exportTags = []string{}
	exportFilterTags = []string{}

	cmd := newExportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	require.NoError(t, cmd.Execute())
	assert.FileExists(t, tmpFile)
	tc.MockSecretService.AssertExpectations(t)
}

func TestExportCommand_EnvPassphraseIsPlumbedIntoRequest(t *testing.T) {
	tc := testutils.NewTestContext(t)
	t.Setenv("ROCKETVAULT_EXPORT_PASSPHRASE", "from-env")

	tmpFile := filepath.Join(t.TempDir(), "export.json")

	tc.MockSecretService.On("ExportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ExportSecretsRequest) bool {
		return r.Encrypt && r.Passphrase == "from-env"
	})).Return([]byte(`{"rocketvault_export":1}`), nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	exportFormat = "json"
	exportFile = tmpFile
	exportEncrypt = true
	exportPassphraseFile = ""
	exportTags = []string{}
	exportFilterTags = []string{}

	cmd := newExportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	require.NoError(t, cmd.Execute())
	tc.MockSecretService.AssertExpectations(t)
}

func TestExportCommand_PlaintextStillWorksAndRequestCarriesNoPassphrase(t *testing.T) {
	tc := testutils.NewTestContext(t)

	tmpFile := filepath.Join(t.TempDir(), "export.json")

	tc.MockSecretService.On("ExportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ExportSecretsRequest) bool {
		return !r.Encrypt && r.Passphrase == ""
	})).Return([]byte(`[]`), nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	exportFormat = "json"
	exportFile = tmpFile
	exportEncrypt = false
	exportPassphraseFile = ""
	exportTags = []string{}
	exportFilterTags = []string{}

	cmd := newExportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	require.NoError(t, cmd.Execute())
	assert.FileExists(t, tmpFile)
	tc.MockSecretService.AssertExpectations(t)
}

// TestExportCommand_EncryptFalseWithPassphraseFile_Errors guards the flag
// combination B36's original fix never considered: --passphrase-file
// supplied alongside --encrypt=false. Silently dropping the passphrase file
// and writing plaintext would reproduce B36's exact failure shape, so the
// command must refuse instead.
func TestExportCommand_EncryptFalseWithPassphraseFile_Errors(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService).Maybe()

	dir := t.TempDir()
	passFile := filepath.Join(dir, "pass.txt")
	require.NoError(t, os.WriteFile(passFile, []byte("s3cret\n"), 0o600))
	tmpFile := filepath.Join(dir, "export.json")

	exportFormat = "json"
	exportFile = tmpFile
	exportEncrypt = false
	exportPassphraseFile = passFile
	exportTags = []string{}
	exportFilterTags = []string{}
	t.Cleanup(func() { exportPassphraseFile = "" })

	cmd := newExportTestCmd(tmpFile)
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--passphrase-file")
	assert.Contains(t, err.Error(), "--encrypt=false")
	assert.NoFileExists(t, tmpFile)
	tc.MockSecretService.AssertNotCalled(t, "ExportSecrets", mock.Anything, mock.Anything)
}
