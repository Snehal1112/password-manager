package vaults_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// setupWebhookTestMasterKey configures a deterministic master key so
// common.EncryptSecret/DecryptSecret work in this package's tests, mirroring
// setupKeyTestMasterKey in internal/services/keys/key_service_extended_test.go.
func setupWebhookTestMasterKey() {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	viper.Set("master_key", base64.StdEncoding.EncodeToString(k))
}

// newWebhookTestLogger returns a minimal *logging.Logger, mirroring the
// pattern used across internal/services/keys tests. logging.Logger has no
// standalone constructor (only InitLogger, which does file/rotation setup we
// don't want here), so tests build it directly from an embedded logrus.Logger.
func newWebhookTestLogger() *logging.Logger {
	return &logging.Logger{Logger: logrus.New()}
}

// fakeWebhookRepo is an in-memory VaultWebhookRepositoryInterface. A hand-
// written fake rather than a testify mock: these tests assert on stored state
// across successive calls, which a fake expresses far more directly.
type fakeWebhookRepo struct {
	rows    map[uuid.UUID]*model.VaultWebhookConfig
	upserts int
	failGet error
}

func newFakeWebhookRepo() *fakeWebhookRepo {
	return &fakeWebhookRepo{rows: map[uuid.UUID]*model.VaultWebhookConfig{}}
}

func (f *fakeWebhookRepo) Upsert(_ context.Context, cfg *model.VaultWebhookConfig) error {
	f.upserts++
	clone := *cfg
	f.rows[cfg.VaultID] = &clone
	return nil
}

func (f *fakeWebhookRepo) GetByVaultID(_ context.Context, vaultID uuid.UUID) (*model.VaultWebhookConfig, error) {
	if f.failGet != nil {
		return nil, f.failGet
	}
	cfg, ok := f.rows[vaultID]
	if !ok {
		return nil, repositories.ErrNotFound
	}
	clone := *cfg
	return &clone, nil
}

func (f *fakeWebhookRepo) DeleteByVaultID(_ context.Context, vaultID uuid.UUID) error {
	delete(f.rows, vaultID)
	return nil
}

func newWebhookService(repo repositories.VaultWebhookRepositoryInterface) vaults.VaultWebhookService {
	return vaults.NewVaultWebhookService(repo, newWebhookTestLogger())
}

func TestWebhookService_Upsert_CreateMintsAndReturnsSecret(t *testing.T) {
	setupWebhookTestMasterKey()
	repo := newFakeWebhookRepo()
	svc := newWebhookService(repo)
	vaultID := uuid.New()

	cfg, secret, err := svc.Upsert(context.Background(), vaultID,
		vaults.UpsertWebhookRequest{URL: "https://hooks.example/rv"}, uuid.New())
	require.NoError(t, err)

	assert.NotEmpty(t, secret, "create must mint and return a secret")
	assert.Equal(t, "https://hooks.example/rv", cfg.URL)
	assert.True(t, cfg.Enabled, "enabled defaults to true on create")

	// The stored value is ciphertext that decrypts back to what we returned.
	assert.NotEqual(t, secret, cfg.SigningSecretEncrypted, "the secret must be stored encrypted")
	decrypted, err := common.DecryptSecret(cfg.SigningSecretEncrypted)
	require.NoError(t, err)
	assert.Equal(t, secret, decrypted)
}

// TestWebhookService_Upsert_SecretsAreUnpredictable guards the crypto/rand
// source: a constant or a counter would pass every other test in this file.
func TestWebhookService_Upsert_SecretsAreUnpredictable(t *testing.T) {
	setupWebhookTestMasterKey()
	svc := newWebhookService(newFakeWebhookRepo())
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		_, secret, err := svc.Upsert(context.Background(), uuid.New(),
			vaults.UpsertWebhookRequest{URL: "https://hooks.example/rv"}, uuid.New())
		require.NoError(t, err)
		require.False(t, seen[secret], "minted a duplicate secret on iteration %d", i)
		require.GreaterOrEqual(t, len(secret), 40, "32 random bytes must not base64 to fewer than 40 chars")
		seen[secret] = true
	}
}

func TestWebhookService_Upsert_UpdateWithoutRotateKeepsSecret(t *testing.T) {
	setupWebhookTestMasterKey()
	repo := newFakeWebhookRepo()
	svc := newWebhookService(repo)
	ctx, vaultID := context.Background(), uuid.New()

	created, firstSecret, err := svc.Upsert(ctx, vaultID,
		vaults.UpsertWebhookRequest{URL: "https://first.example"}, uuid.New())
	require.NoError(t, err)
	require.NotEmpty(t, firstSecret)

	updated, secret, err := svc.Upsert(ctx, vaultID,
		vaults.UpsertWebhookRequest{URL: "https://second.example"}, uuid.New())
	require.NoError(t, err)

	assert.Empty(t, secret, "an update that did not rotate must return no secret")
	assert.Equal(t, "https://second.example", updated.URL)
	assert.Equal(t, created.SigningSecretEncrypted, updated.SigningSecretEncrypted,
		"the stored ciphertext must be byte-identical when not rotating")
}

func TestWebhookService_Upsert_RotateMintsNewSecret(t *testing.T) {
	setupWebhookTestMasterKey()
	repo := newFakeWebhookRepo()
	svc := newWebhookService(repo)
	ctx, vaultID := context.Background(), uuid.New()

	created, firstSecret, err := svc.Upsert(ctx, vaultID,
		vaults.UpsertWebhookRequest{URL: "https://a.example"}, uuid.New())
	require.NoError(t, err)

	rotated, secondSecret, err := svc.Upsert(ctx, vaultID,
		vaults.UpsertWebhookRequest{URL: "https://a.example", RotateSecret: true}, uuid.New())
	require.NoError(t, err)

	assert.NotEmpty(t, secondSecret, "a rotate must return the new secret")
	assert.NotEqual(t, firstSecret, secondSecret)
	assert.NotEqual(t, created.SigningSecretEncrypted, rotated.SigningSecretEncrypted)

	decrypted, err := common.DecryptSecret(rotated.SigningSecretEncrypted)
	require.NoError(t, err)
	assert.Equal(t, secondSecret, decrypted)
}

// TestWebhookService_Upsert_NilEnabledKeepsStoredValue is the regression test
// for the bare-bool trap the *bool type exists to avoid: a URL-only update
// must not silently disable the webhook.
func TestWebhookService_Upsert_NilEnabledKeepsStoredValue(t *testing.T) {
	setupWebhookTestMasterKey()
	repo := newFakeWebhookRepo()
	svc := newWebhookService(repo)
	ctx, vaultID := context.Background(), uuid.New()
	disabled := false

	_, _, err := svc.Upsert(ctx, vaultID,
		vaults.UpsertWebhookRequest{URL: "https://a.example", Enabled: &disabled}, uuid.New())
	require.NoError(t, err)

	updated, _, err := svc.Upsert(ctx, vaultID,
		vaults.UpsertWebhookRequest{URL: "https://b.example"}, uuid.New()) // Enabled nil
	require.NoError(t, err)
	assert.False(t, updated.Enabled, "a nil Enabled must keep the stored value, not reset it")

	enabled := true
	reenabled, _, err := svc.Upsert(ctx, vaultID,
		vaults.UpsertWebhookRequest{URL: "https://b.example", Enabled: &enabled}, uuid.New())
	require.NoError(t, err)
	assert.True(t, reenabled.Enabled)
}

func TestWebhookService_Upsert_RejectsBadURLs(t *testing.T) {
	svc := newWebhookService(newFakeWebhookRepo())
	for _, tc := range []struct{ name, url string }{
		{"http scheme", "http://hooks.example/rv"},
		{"no scheme", "hooks.example/rv"},
		{"scheme only, no host", "https://"},
		{"empty", ""},
		{"unparseable", "https://exa mple.com/\x7f"},
		{"not a url", "::::"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := svc.Upsert(context.Background(), uuid.New(),
				vaults.UpsertWebhookRequest{URL: tc.url}, uuid.New())
			require.Error(t, err)
			assert.True(t, errors.Is(err, vaults.ErrInvalidWebhookURL),
				"expected ErrInvalidWebhookURL, got %v", err)
		})
	}
}

// TestWebhookService_Upsert_RejectsBadURLBeforeTouchingRepo proves validation
// happens first, so an invalid request never reaches storage.
func TestWebhookService_Upsert_RejectsBadURLBeforeTouchingRepo(t *testing.T) {
	repo := newFakeWebhookRepo()
	svc := newWebhookService(repo)

	_, _, err := svc.Upsert(context.Background(), uuid.New(),
		vaults.UpsertWebhookRequest{URL: "http://insecure.example"}, uuid.New())
	require.Error(t, err)
	assert.Zero(t, repo.upserts, "an invalid URL must not reach the repository")
}

func TestWebhookService_Get_UnknownReturnsErrWebhookNotFound(t *testing.T) {
	svc := newWebhookService(newFakeWebhookRepo())

	_, err := svc.Get(context.Background(), uuid.New())
	require.Error(t, err)
	assert.True(t, errors.Is(err, vaults.ErrWebhookNotFound), "expected ErrWebhookNotFound, got %v", err)
}

// TestWebhookService_Get_RealRepoErrorIsNotNotFound keeps a database outage
// from being reported to the caller as "no webhook configured".
func TestWebhookService_Get_RealRepoErrorIsNotNotFound(t *testing.T) {
	repo := newFakeWebhookRepo()
	repo.failGet = errors.New("database is locked")
	svc := newWebhookService(repo)

	_, err := svc.Get(context.Background(), uuid.New())
	require.Error(t, err)
	assert.False(t, errors.Is(err, vaults.ErrWebhookNotFound))
}

func TestWebhookService_Get_DoesNotDecrypt(t *testing.T) {
	setupWebhookTestMasterKey()
	repo := newFakeWebhookRepo()
	svc := newWebhookService(repo)
	ctx, vaultID := context.Background(), uuid.New()

	_, secret, err := svc.Upsert(ctx, vaultID,
		vaults.UpsertWebhookRequest{URL: "https://a.example"}, uuid.New())
	require.NoError(t, err)

	got, err := svc.Get(ctx, vaultID)
	require.NoError(t, err)
	assert.NotEqual(t, secret, got.SigningSecretEncrypted, "Get must return ciphertext, never plaintext")
}

func TestWebhookService_Delete(t *testing.T) {
	setupWebhookTestMasterKey()
	repo := newFakeWebhookRepo()
	svc := newWebhookService(repo)
	ctx, vaultID := context.Background(), uuid.New()
	_, _, err := svc.Upsert(ctx, vaultID,
		vaults.UpsertWebhookRequest{URL: "https://a.example"}, uuid.New())
	require.NoError(t, err)

	require.NoError(t, svc.Delete(ctx, vaultID, uuid.New()))

	_, err = svc.Get(ctx, vaultID)
	assert.True(t, errors.Is(err, vaults.ErrWebhookNotFound))
}

// hookedWebhookService builds a VaultWebhookService whose logger is a fresh
// *logrus.Logger with a test hook attached, so callers can inspect exactly
// what LogAuditInfo emitted.
func hookedWebhookService(repo repositories.VaultWebhookRepositoryInterface) (vaults.VaultWebhookService, *logrustest.Hook) {
	l := logrus.New()
	hook := logrustest.NewLocal(l)
	log := &logging.Logger{Logger: l}
	return vaults.NewVaultWebhookService(repo, log), hook
}

// assertNoSecretLeak fails the test if secret appears anywhere in an audit
// log entry -- message or any field value.
func assertNoSecretLeak(t *testing.T, hook *logrustest.Hook, secret string) {
	t.Helper()
	require.NotEmpty(t, secret, "test bug: secret must be non-empty for this check to mean anything")
	for _, entry := range hook.AllEntries() {
		assert.NotContains(t, entry.Message, secret, "the signing secret must never reach the audit log message")
		for k, v := range entry.Data {
			if s, ok := v.(string); ok {
				assert.NotContains(t, s, secret, "the signing secret must never reach audit log field %q", k)
			}
		}
	}
}

// TestWebhookService_Upsert_Create_LogsAuditRecord pins that a create reaches
// the audit trail (via LogAuditInfo, the same call vault_service.go's
// create/update/delete/recover/purge use) with operation "create_vault_webhook"
// and rotated=true (creating always mints a secret).
func TestWebhookService_Upsert_Create_LogsAuditRecord(t *testing.T) {
	setupWebhookTestMasterKey()
	svc, hook := hookedWebhookService(newFakeWebhookRepo())
	vaultID := uuid.New()

	actor := uuid.New()
	_, secret, err := svc.Upsert(context.Background(), vaultID,
		vaults.UpsertWebhookRequest{URL: "https://hooks.example/rv"}, actor)
	require.NoError(t, err)
	require.NotEmpty(t, secret)

	entries := hook.AllEntries()
	require.Len(t, entries, 1, "Upsert must write exactly one audit record")
	entry := entries[0]
	assert.Equal(t, "create_vault_webhook", entry.Data["operation"])
	assert.Equal(t, "success", entry.Data["status"])
	// user_id is what LogAuditInfo hands to PersistAudit, so this is the field
	// that reaches the audit_logs table. Without it the record says a webhook
	// was repointed but not by whom.
	assert.Equal(t, actor.String(), entry.Data["user_id"],
		"the acting principal must be attributed in the audit record")
	assert.Contains(t, entry.Message, vaultID.String())
	assert.Contains(t, entry.Message, "https://hooks.example/rv")
	assert.Contains(t, entry.Message, "rotated=true")

	assertNoSecretLeak(t, hook, secret)
}

// TestWebhookService_Upsert_UpdateWithRotate_LogsAuditRecord pins that an
// update distinguishes a rotation in its audit record.
func TestWebhookService_Upsert_UpdateWithRotate_LogsAuditRecord(t *testing.T) {
	setupWebhookTestMasterKey()
	repo := newFakeWebhookRepo()
	svc, hook := hookedWebhookService(repo)
	ctx, vaultID := context.Background(), uuid.New()

	creator, rotator := uuid.New(), uuid.New()
	_, firstSecret, err := svc.Upsert(ctx, vaultID, vaults.UpsertWebhookRequest{URL: "https://a.example"}, creator)
	require.NoError(t, err)
	hook.Reset()

	_, secondSecret, err := svc.Upsert(ctx, vaultID,
		vaults.UpsertWebhookRequest{URL: "https://a.example", RotateSecret: true}, rotator)
	require.NoError(t, err)
	require.NotEmpty(t, secondSecret)

	entries := hook.AllEntries()
	require.Len(t, entries, 1)
	entry := entries[0]
	assert.Equal(t, "update_vault_webhook", entry.Data["operation"])
	assert.Contains(t, entry.Message, "rotated=true")
	// Distinct actors for the create and the rotate: this is the scenario the
	// attribution exists for -- a different principal rotating someone else's
	// signing secret must be distinguishable in the trail.
	assert.Equal(t, rotator.String(), entry.Data["user_id"])
	assert.NotEqual(t, creator.String(), entry.Data["user_id"])

	assertNoSecretLeak(t, hook, firstSecret)
	assertNoSecretLeak(t, hook, secondSecret)
}

// TestWebhookService_Upsert_UpdateWithoutRotate_LogsAuditRecord pins that an
// update that did not rotate records rotated=false, and -- since no new
// secret was minted -- confirms the audit record can't be leaking one.
func TestWebhookService_Upsert_UpdateWithoutRotate_LogsAuditRecord(t *testing.T) {
	setupWebhookTestMasterKey()
	repo := newFakeWebhookRepo()
	svc, hook := hookedWebhookService(repo)
	ctx, vaultID := context.Background(), uuid.New()

	actor := uuid.New()
	_, firstSecret, err := svc.Upsert(ctx, vaultID, vaults.UpsertWebhookRequest{URL: "https://a.example"}, actor)
	require.NoError(t, err)
	hook.Reset()

	_, secret, err := svc.Upsert(ctx, vaultID, vaults.UpsertWebhookRequest{URL: "https://b.example"}, actor)
	require.NoError(t, err)
	assert.Empty(t, secret, "an update that did not rotate must return no secret")

	entries := hook.AllEntries()
	require.Len(t, entries, 1)
	entry := entries[0]
	assert.Equal(t, "update_vault_webhook", entry.Data["operation"])
	assert.Contains(t, entry.Message, "rotated=false")
	assert.Equal(t, actor.String(), entry.Data["user_id"])

	assertNoSecretLeak(t, hook, firstSecret)
}

// TestWebhookService_Delete_LogsAuditRecord pins that Delete -- previously
// silent -- now writes an audit record.
func TestWebhookService_Delete_LogsAuditRecord(t *testing.T) {
	setupWebhookTestMasterKey()
	repo := newFakeWebhookRepo()
	svc, hook := hookedWebhookService(repo)
	ctx, vaultID := context.Background(), uuid.New()

	creator, deleter := uuid.New(), uuid.New()
	_, secret, err := svc.Upsert(ctx, vaultID, vaults.UpsertWebhookRequest{URL: "https://a.example"}, creator)
	require.NoError(t, err)
	hook.Reset()

	require.NoError(t, svc.Delete(ctx, vaultID, deleter))

	entries := hook.AllEntries()
	require.Len(t, entries, 1, "Delete must write exactly one audit record")
	entry := entries[0]
	assert.Equal(t, "delete_vault_webhook", entry.Data["operation"])
	assert.Contains(t, entry.Message, vaultID.String())
	assert.Equal(t, deleter.String(), entry.Data["user_id"],
		"the deleting principal must be attributed, not the principal who created the config")

	assertNoSecretLeak(t, hook, secret)
}

func TestWebhookService_Upsert_StampsTimestamps(t *testing.T) {
	setupWebhookTestMasterKey()
	svc := newWebhookService(newFakeWebhookRepo())
	before := time.Now().UTC().Add(-time.Second)

	cfg, _, err := svc.Upsert(context.Background(), uuid.New(),
		vaults.UpsertWebhookRequest{URL: "https://a.example"}, uuid.New())
	require.NoError(t, err)
	assert.False(t, cfg.CreatedAt.Before(before))
	assert.False(t, cfg.UpdatedAt.Before(before))
}
