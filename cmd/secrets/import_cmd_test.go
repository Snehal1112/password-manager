package secrets

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	authzServices "rocketvault/internal/services/authorization"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

func TestImportCommand_CallsServiceImport(t *testing.T) {
	tc := testutils.NewTestContext(t)

	// The request must carry the resolved vault scope, not the zero-value
	// Scope: a zero Scope has kind ScopeInvalid and every repository query
	// rejects it, so this assertion catches the "Scope never set" regression
	// that a service-level mock alone would miss.
	//
	// The actor must be the real authenticated user, never uuid.Nil:
	// ImportSecrets derives each new secret's owner from Scope.ActorID, so a
	// nil actor orphans every imported row (and violates the PostgreSQL
	// foreign key).
	wantScope := model.NewVaultScope(tc.TestVaultID, tc.TestUserID)
	tc.MockSecretService.On("ImportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ImportSecretsRequest) bool {
		return r.Format == "json" && r.Scope == wantScope
	})).Return(&secretServices.ImportResult{ImportedCount: 2}, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

	// Assert the exact args reaching both authorization checks, not just
	// "some" values — a transposed action/op or swapped principal/vault must
	// fail this test, not pass it.
	roles := &testutils.MockRoleAssignmentService{}
	roles.On("HasDataAction", mock.Anything, tc.TestUserID, tc.TestVaultID, model.ActionSecretsSet).
		Return(true, nil).Once()
	policies := &testutils.MockAccessPolicyService{}
	policies.On("CheckAccess", mock.Anything, tc.TestUserID, model.PolicyResourceSecrets, model.OpImport, tc.TestVaultID).
		Return(authzServices.AccessAllowed, nil).Once()
	tc.MockContainer.RoleAssignmentService = roles
	tc.MockContainer.AccessPolicyService = policies

	tmpFile := t.TempDir() + "/import.json"
	os.WriteFile(tmpFile, []byte(`{}`), 0o600)

	// Reset package-level vars.
	importFormat = "json"
	importFile = tmpFile
	importEncrypted = false
	importOverwrite = false

	cmd := &cobra.Command{Use: "import", RunE: secretsImportCmd.RunE}
	cmd.Flags().StringVarP(&importFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&importFile, "file", "i", tmpFile, "")
	cmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", false, "")
	cmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.NoError(t, err)
	tc.MockSecretService.AssertExpectations(t)
	roles.AssertExpectations(t)
	policies.AssertExpectations(t)
}

func TestImportCommand_FileNotFound(t *testing.T) {
	tc := testutils.NewTestContext(t)

	importFormat = "json"
	importFile = "/nonexistent/path/import.json"
	importEncrypted = false
	importOverwrite = false

	cmd := &cobra.Command{Use: "import", RunE: secretsImportCmd.RunE}
	cmd.Flags().StringVarP(&importFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&importFile, "file", "i", "/nonexistent/path/import.json", "")
	cmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", false, "")
	cmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "import file does not exist")
}

func TestImportCommand_Forbidden(t *testing.T) {
	tc := testutils.NewTestContext(t)

	denyRoles := &testutils.MockRoleAssignmentService{}
	denyRoles.On("HasDataAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(false, nil).Maybe()
	tc.MockContainer.RoleAssignmentService = denyRoles

	tmpFile := t.TempDir() + "/import.json"
	os.WriteFile(tmpFile, []byte(`{}`), 0o600)

	importFormat = "json"
	importFile = tmpFile
	importEncrypted = false
	importOverwrite = false

	cmd := &cobra.Command{Use: "import", RunE: secretsImportCmd.RunE}
	cmd.Flags().StringVarP(&importFormat, "format", "f", "json", "")
	cmd.Flags().StringVarP(&importFile, "file", "i", tmpFile, "")
	cmd.Flags().BoolVarP(&importEncrypted, "encrypted", "e", false, "")
	cmd.Flags().BoolVarP(&importOverwrite, "overwrite", "w", false, "")
	cmd.SetContext(tc.Ctx)

	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
	tc.MockSecretService.AssertNotCalled(t, "ImportSecrets", mock.Anything, mock.Anything)
}
