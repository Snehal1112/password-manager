package secrets

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

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
