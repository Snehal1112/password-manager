package vaultwebhook

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	vaultServices "rocketvault/internal/services/vaults"
)

// TestVaultWebhookDelete_ServiceErrorNotSpecialCased proves the removed
// errors.Is(err, ErrWebhookNotFound) branch is gone: VaultWebhookService.Delete
// is idempotent on an absent config (it calls repo.DeleteByVaultID and treats
// deleting nothing as success -- see webhook_service.go's Delete), so the CLI
// never legitimately observes that sentinel from a real call. Any error the
// service does return -- including, artificially, this sentinel itself --
// must surface as the generic failure message, not be re-interpreted as
// "not configured".
func TestVaultWebhookDelete_ServiceErrorNotSpecialCased(t *testing.T) {
	tc := testutils.NewTestContext(t)
	fake := &fakeWebhookSvc{deleteErr: vaultServices.ErrWebhookNotFound}
	tc.MockContainer.VaultWebhookService = fake

	cmd, _ := newVaultWebhookCmd(tc.Ctx)
	cmd.SetArgs([]string{"delete"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete webhook failed")
	assert.NotContains(t, err.Error(), "no webhook configured for vault")
}
