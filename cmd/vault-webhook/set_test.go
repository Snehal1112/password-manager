package vaultwebhook

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	authzServices "rocketvault/internal/services/authorization"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// fakeWebhookSvc is a minimal VaultWebhookService that records whether its
// methods were reached, so a denial test can prove the authz gate ran first.
type fakeWebhookSvc struct {
	upsertCalled bool
	upsertVault  uuid.UUID
	upsertReq    vaultServices.UpsertWebhookRequest
	upsertResp   *model.VaultWebhookConfig
	upsertSecret string
	upsertErr    error

	getCalled bool
	getResp   *model.VaultWebhookConfig
	getErr    error

	deleteCalled bool
	deleteErr    error
}

func (f *fakeWebhookSvc) Upsert(_ context.Context, vaultID uuid.UUID, req vaultServices.UpsertWebhookRequest) (*model.VaultWebhookConfig, string, error) {
	f.upsertCalled = true
	f.upsertVault = vaultID
	f.upsertReq = req
	return f.upsertResp, f.upsertSecret, f.upsertErr
}

func (f *fakeWebhookSvc) Get(_ context.Context, _ uuid.UUID) (*model.VaultWebhookConfig, error) {
	f.getCalled = true
	return f.getResp, f.getErr
}

func (f *fakeWebhookSvc) Delete(_ context.Context, _ uuid.UUID) error {
	f.deleteCalled = true
	return f.deleteErr
}

// newVaultWebhookCmd wires set/get/delete onto a fresh parent command bound
// to ctx, and returns the parent plus its captured output buffer.
func newVaultWebhookCmd(ctx context.Context) (*cobra.Command, *bytes.Buffer) {
	parent := &cobra.Command{Use: "vault-webhook"}
	InitVaultWebhookSet(parent)
	InitVaultWebhookGet(parent)
	InitVaultWebhookDelete(parent)
	parent.SetContext(ctx)
	var out bytes.Buffer
	parent.SetOut(&out)
	parent.SetErr(&out)
	return parent, &out
}

// TestVaultWebhookSet_MissingURLIsFlagError proves --url is required.
func TestVaultWebhookSet_MissingURLIsFlagError(t *testing.T) {
	tc := testutils.NewTestContext(t)
	tc.MockContainer.VaultWebhookService = &fakeWebhookSvc{}

	cmd, _ := newVaultWebhookCmd(tc.Ctx)
	cmd.SetArgs([]string{"set"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--url is required")
}

// TestVaultWebhookSet_Create prints the minted secret and the one-time
// notice, and never leaks the secret through the logger.
func TestVaultWebhookSet_Create(t *testing.T) {
	// Hook the global logrus logger so we can prove nothing our code emits
	// carries the secret -- the CLI-side guard against cmd/users/create.go:91's
	// habit of logging a freshly minted secret.
	hook := logrustest.NewGlobal()
	defer logrus.StandardLogger().ReplaceHooks(make(logrus.LevelHooks))

	tc := testutils.NewTestContext(t)
	const secret = "brand-new-signing-secret"
	fake := &fakeWebhookSvc{
		upsertResp: &model.VaultWebhookConfig{
			URL:     "https://hooks.example/rocketvault",
			Enabled: true,
		},
		upsertSecret: secret,
	}
	tc.MockContainer.VaultWebhookService = fake

	cmd, out := newVaultWebhookCmd(tc.Ctx)
	cmd.SetArgs([]string{"set", "--url", "https://hooks.example/rocketvault"})

	require.NoError(t, cmd.Execute())
	require.True(t, fake.upsertCalled)
	assert.Contains(t, out.String(), "Signing Secret: "+secret)
	assert.Contains(t, out.String(), "Store the signing secret now")

	for _, entry := range hook.AllEntries() {
		assert.NotContains(t, entry.Message, secret, "the secret must never reach the logger")
		for _, v := range entry.Data {
			if s, ok := v.(string); ok {
				assert.NotContains(t, s, secret, "the secret must never reach the logger")
			}
		}
	}
}

// TestVaultWebhookSet_UpdateWithoutRotate prints NO secret line and no
// notice: the CLI must not invent a field the service did not return.
func TestVaultWebhookSet_UpdateWithoutRotate(t *testing.T) {
	tc := testutils.NewTestContext(t)
	fake := &fakeWebhookSvc{
		upsertResp: &model.VaultWebhookConfig{
			URL:     "https://hooks.example/rocketvault",
			Enabled: true,
		},
		upsertSecret: "", // service minted nothing on this update.
	}
	tc.MockContainer.VaultWebhookService = fake

	cmd, out := newVaultWebhookCmd(tc.Ctx)
	cmd.SetArgs([]string{"set", "--url", "https://hooks.example/rocketvault"})

	require.NoError(t, cmd.Execute())
	require.True(t, fake.upsertCalled)
	assert.False(t, fake.upsertReq.RotateSecret)
	assert.NotContains(t, out.String(), "Signing Secret:")
	assert.NotContains(t, out.String(), "Store the signing secret now")
}

// TestVaultWebhookSet_RotateSecret prints the new secret and passes
// RotateSecret through to the service.
func TestVaultWebhookSet_RotateSecret(t *testing.T) {
	tc := testutils.NewTestContext(t)
	const secret = "rotated-signing-secret"
	fake := &fakeWebhookSvc{
		upsertResp: &model.VaultWebhookConfig{
			URL:     "https://hooks.example/rocketvault",
			Enabled: true,
		},
		upsertSecret: secret,
	}
	tc.MockContainer.VaultWebhookService = fake

	cmd, out := newVaultWebhookCmd(tc.Ctx)
	cmd.SetArgs([]string{"set", "--url", "https://hooks.example/rocketvault", "--rotate-secret"})

	require.NoError(t, cmd.Execute())
	require.True(t, fake.upsertCalled)
	assert.True(t, fake.upsertReq.RotateSecret)
	assert.Contains(t, out.String(), "Signing Secret: "+secret)
}

// TestVaultWebhookSet_EnabledFlagNilWhenUnset proves --enabled reaches the
// service as *bool, nil when the user did not pass the flag -- a bare false
// for an unset flag would silently disable the webhook on a URL-only update.
func TestVaultWebhookSet_EnabledFlagNilWhenUnset(t *testing.T) {
	tc := testutils.NewTestContext(t)
	fake := &fakeWebhookSvc{
		upsertResp: &model.VaultWebhookConfig{URL: "https://hooks.example/rocketvault", Enabled: true},
	}
	tc.MockContainer.VaultWebhookService = fake

	cmd, _ := newVaultWebhookCmd(tc.Ctx)
	cmd.SetArgs([]string{"set", "--url", "https://hooks.example/rocketvault"})

	require.NoError(t, cmd.Execute())
	assert.Nil(t, fake.upsertReq.Enabled)
}

// TestVaultWebhookSet_EnabledFlagExplicit proves an explicitly passed
// --enabled=false reaches the service as a non-nil *bool.
func TestVaultWebhookSet_EnabledFlagExplicit(t *testing.T) {
	tc := testutils.NewTestContext(t)
	fake := &fakeWebhookSvc{
		upsertResp: &model.VaultWebhookConfig{URL: "https://hooks.example/rocketvault", Enabled: false},
	}
	tc.MockContainer.VaultWebhookService = fake

	cmd, _ := newVaultWebhookCmd(tc.Ctx)
	cmd.SetArgs([]string{"set", "--url", "https://hooks.example/rocketvault", "--enabled=false"})

	require.NoError(t, cmd.Execute())
	require.NotNil(t, fake.upsertReq.Enabled)
	assert.False(t, *fake.upsertReq.Enabled)
}

// TestVaultWebhookSet_DeniedWithoutGrant proves an authorization denial
// surfaces as a clear CLI error and the webhook service is never called.
func TestVaultWebhookSet_DeniedWithoutGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	fake := &fakeWebhookSvc{}
	tc.MockContainer.VaultWebhookService = fake
	ctx := nonAdminCtx(tc, &fakePolicySvc{decision: authzServices.AccessFallback})

	cmd, _ := newVaultWebhookCmd(ctx)
	cmd.SetArgs([]string{"set", "--url", "https://hooks.example/rocketvault"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	assert.False(t, fake.upsertCalled, "Upsert must not be reached when the caller is denied")
}

// TestVaultWebhookGet_DeniedWithoutGrant mirrors the set case for get.
func TestVaultWebhookGet_DeniedWithoutGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	fake := &fakeWebhookSvc{}
	tc.MockContainer.VaultWebhookService = fake
	ctx := nonAdminCtx(tc, &fakePolicySvc{decision: authzServices.AccessFallback})

	cmd, _ := newVaultWebhookCmd(ctx)
	cmd.SetArgs([]string{"get"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	assert.False(t, fake.getCalled, "Get must not be reached when the caller is denied")
}

// TestVaultWebhookGet_NeverPrintsSecret proves get shows only URL/Enabled/
// Created/Updated -- no secret line, because the service returns only
// ciphertext and the CLI has no business decrypting it.
func TestVaultWebhookGet_NeverPrintsSecret(t *testing.T) {
	tc := testutils.NewTestContext(t)
	fake := &fakeWebhookSvc{
		getResp: &model.VaultWebhookConfig{
			URL:                    "https://hooks.example/rocketvault",
			Enabled:                true,
			SigningSecretEncrypted: "ciphertext-should-never-print",
		},
	}
	tc.MockContainer.VaultWebhookService = fake

	cmd, out := newVaultWebhookCmd(tc.Ctx)
	cmd.SetArgs([]string{"get"})

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "URL: https://hooks.example/rocketvault")
	assert.NotContains(t, out.String(), "Secret")
	assert.NotContains(t, out.String(), "ciphertext-should-never-print")
}

// TestVaultWebhookGet_NotFound surfaces ErrWebhookNotFound as a clear message.
func TestVaultWebhookGet_NotFound(t *testing.T) {
	tc := testutils.NewTestContext(t)
	fake := &fakeWebhookSvc{getErr: vaultServices.ErrWebhookNotFound}
	tc.MockContainer.VaultWebhookService = fake

	cmd, _ := newVaultWebhookCmd(tc.Ctx)
	cmd.SetArgs([]string{"get"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no webhook configured for vault")
}

// TestVaultWebhookDelete_DeniedWithoutGrant mirrors the set/get denial cases
// for delete.
func TestVaultWebhookDelete_DeniedWithoutGrant(t *testing.T) {
	tc := testutils.NewTestContext(t)
	fake := &fakeWebhookSvc{}
	tc.MockContainer.VaultWebhookService = fake
	ctx := nonAdminCtx(tc, &fakePolicySvc{decision: authzServices.AccessFallback})

	cmd, _ := newVaultWebhookCmd(ctx)
	cmd.SetArgs([]string{"delete"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	assert.False(t, fake.deleteCalled, "Delete must not be reached when the caller is denied")
}

// TestVaultWebhookDelete_Confirms prints a one-line confirmation on success.
func TestVaultWebhookDelete_Confirms(t *testing.T) {
	tc := testutils.NewTestContext(t)
	fake := &fakeWebhookSvc{}
	tc.MockContainer.VaultWebhookService = fake

	cmd, out := newVaultWebhookCmd(tc.Ctx)
	cmd.SetArgs([]string{"delete"})

	require.NoError(t, cmd.Execute())
	assert.True(t, fake.deleteCalled)
	assert.Contains(t, out.String(), "deleted")
}
