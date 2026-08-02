package secrets

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

func TestExportCommand_CallsServiceExport(t *testing.T) {
	tc := testutils.NewTestContext(t)

	// The request must carry an owner scope built from the real authenticated
	// user, not the zero-value Scope and not a vault scope. A zero Scope has
	// kind ScopeInvalid and every repository query rejects it; a vault scope
	// would make `secrets export` write every vault member's decrypted secret
	// values into the caller's local file.
	wantScope := model.NewOwnerScope(tc.TestVaultID, tc.TestUserID)
	tc.MockSecretService.On("ExportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ExportSecretsRequest) bool {
		return r.Format == "json" && r.Scope == wantScope
	})).Return([]byte(`{"secrets":[]}`), nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

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
}
