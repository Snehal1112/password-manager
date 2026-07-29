package secrets

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	secretServices "rocketvault/internal/services/secrets"
)

func TestImportCommand_CallsServiceImport(t *testing.T) {
	tc := testutils.NewTestContext(t)

	tc.MockSecretService.On("ImportSecrets", mock.Anything, mock.MatchedBy(func(r secretServices.ImportSecretsRequest) bool {
		return r.Format == "json"
	})).Return(&secretServices.ImportResult{ImportedCount: 2}, nil)
	tc.MockContainer.On("GetSecretService").Return(tc.MockSecretService)

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
