// Package api — unit tests for vault_webhook.go handlers.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	authzServices "rocketvault/internal/services/authorization"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// --- webhookStub: a VaultWebhookService test double that records whether it
// was ever invoked, so authorization-must-precede-service-call tests can
// assert the service was never touched. ---

type webhookStub struct {
	called bool

	// gotActor records the principal the handler attributed the change to, so
	// tests can prove the caller's identity is threaded through to the audit
	// trail rather than dropped at the handler boundary.
	gotActor uuid.UUID

	cfg             *model.VaultWebhookConfig
	plaintextSecret string
	upsertErr       error
	getErr          error
	deleteErr       error
}

func (s *webhookStub) Upsert(_ context.Context, _ uuid.UUID, _ vaultServices.UpsertWebhookRequest, actor uuid.UUID) (*model.VaultWebhookConfig, string, error) {
	s.called = true
	s.gotActor = actor
	if s.upsertErr != nil {
		return nil, "", s.upsertErr
	}
	return s.cfg, s.plaintextSecret, nil
}

func (s *webhookStub) Get(_ context.Context, _ uuid.UUID) (*model.VaultWebhookConfig, error) {
	s.called = true
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.cfg, nil
}

func (s *webhookStub) Delete(_ context.Context, _ uuid.UUID, actor uuid.UUID) error {
	s.called = true
	s.gotActor = actor
	return s.deleteErr
}

// newWebhookTestAPI builds an API with a real vault service (backed by
// vaultFakeRepo, pre-seeded with a "prod" vault) and the given webhook stub,
// wired the same way newVaultTestAPIWithContainer wires its container in
// api/vault_test.go.
func newWebhookTestAPI(t *testing.T, stub *webhookStub, policySvc authzServices.AccessPolicyService) (*API, uuid.UUID) {
	t.Helper()
	repo := newVaultFakeRepo()
	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	vaultSvc := vaultServices.NewVaultService(repo, vaultNoopCascade{}, nil)
	cont := &vaultSvcTestContainer{
		vaultSvc:        vaultSvc,
		vaultWebhookSvc: stub,
		policySvc:       policySvc,
		logger:          userTestLog(),
	}
	return newVaultTestAPIWithContainer(cont), id
}

func TestUpsertVaultWebhook_Create_Returns200WithSecret(t *testing.T) {
	stub := &webhookStub{
		cfg:             &model.VaultWebhookConfig{URL: "https://hooks.example/rv", Enabled: true},
		plaintextSecret: "s3cr3t",
	}
	api, _ := newWebhookTestAPI(t, stub, &mockAccessPolicyService{})

	body := []byte(`{"url":"https://hooks.example/rv"}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/vaults/prod/webhook", body)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"signing_secret":"s3cr3t"`)
	assert.Contains(t, w.Body.String(), `"url":"https://hooks.example/rv"`)
	assert.True(t, stub.called)
	// The authenticated caller must reach the service so the change is
	// attributable in audit_logs. resolveAndAuthorizeVault already resolves
	// this identity to run CanManageVault; dropping it afterwards would leave
	// a record saying a webhook was repointed but not by whom.
	assert.Equal(t, uuid.MustParse(vaultTestUserID), stub.gotActor,
		"the authenticated caller must be passed to the service for the audit trail")
}

// TestDeleteVaultWebhook_PassesActor is the delete-side counterpart: delete is
// the destructive operation on this resource, so its audit record is the one
// most worth attributing.
func TestDeleteVaultWebhook_PassesActor(t *testing.T) {
	stub := &webhookStub{}
	api, _ := newWebhookTestAPI(t, stub, &mockAccessPolicyService{})

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/prod/webhook", nil)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.True(t, stub.called)
	assert.Equal(t, uuid.MustParse(vaultTestUserID), stub.gotActor)
}

func TestUpsertVaultWebhook_UpdateWithoutRotate_OmitsSecret(t *testing.T) {
	stub := &webhookStub{
		cfg:             &model.VaultWebhookConfig{URL: "https://hooks.example/rv", Enabled: true},
		plaintextSecret: "",
	}
	api, _ := newWebhookTestAPI(t, stub, &mockAccessPolicyService{})

	body := []byte(`{"url":"https://hooks.example/rv"}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/vaults/prod/webhook", body)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, w.Body.String(), "signing_secret")

	var resp model.VaultWebhookConfigResponse
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "https://hooks.example/rv", resp.URL)
}

// TestGetVaultWebhook_NeverReturnsSecret is the load-bearing leak test: even
// if the service returned a config carrying ciphertext, the HTTP response
// must not contain it in any form.
func TestGetVaultWebhook_NeverReturnsSecret(t *testing.T) {
	stub := &webhookStub{
		cfg: &model.VaultWebhookConfig{
			URL:                    "https://hooks.example/rv",
			Enabled:                true,
			SigningSecretEncrypted: "CIPHERTEXT-SENTINEL",
		},
	}
	api, _ := newWebhookTestAPI(t, stub, &mockAccessPolicyService{})

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/prod/webhook", nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, w.Body.String(), "signing_secret")
	assert.NotContains(t, w.Body.String(), "CIPHERTEXT-SENTINEL")
}

func TestGetVaultWebhook_NotConfigured_Returns404(t *testing.T) {
	stub := &webhookStub{getErr: vaultServices.ErrWebhookNotFound}
	api, _ := newWebhookTestAPI(t, stub, &mockAccessPolicyService{})

	w := doVaultRequest(api, http.MethodGet, "/api/v1/vaults/prod/webhook", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestUpsertVaultWebhook_InvalidURL_Returns400 proves a client error (a
// rejected URL) surfaces as 400, not a misleading 500.
func TestUpsertVaultWebhook_InvalidURL_Returns400(t *testing.T) {
	stub := &webhookStub{upsertErr: vaultServices.ErrInvalidWebhookURL}
	api, _ := newWebhookTestAPI(t, stub, &mockAccessPolicyService{})

	body := []byte(`{"url":"not-a-url"}`)
	w := doVaultRequest(api, http.MethodPut, "/api/v1/vaults/prod/webhook", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpsertVaultWebhook_MalformedBody_Returns400(t *testing.T) {
	stub := &webhookStub{}
	api, _ := newWebhookTestAPI(t, stub, &mockAccessPolicyService{})

	w := doVaultRequest(api, http.MethodPut, "/api/v1/vaults/prod/webhook", []byte(`{`))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.False(t, stub.called, "the webhook service must not be invoked for a malformed body")
}

// TestVaultWebhook_UnknownVault_Returns404 confirms all three handlers 404 on
// a vault that doesn't exist, and that the webhook service is never touched
// for a vault that failed to resolve.
func TestVaultWebhook_UnknownVault_Returns404(t *testing.T) {
	cases := []struct {
		name   string
		method string
		body   []byte
	}{
		{"PUT", http.MethodPut, []byte(`{"url":"https://hooks.example/rv"}`)},
		{"GET", http.MethodGet, nil},
		{"DELETE", http.MethodDelete, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &webhookStub{}
			api, _ := newWebhookTestAPI(t, stub, &mockAccessPolicyService{})

			w := doVaultRequest(api, tc.method, "/api/v1/vaults/ghost/webhook", tc.body)

			assert.Equal(t, http.StatusNotFound, w.Code)
			assert.False(t, stub.called, "the webhook service must not be invoked when the vault does not resolve")
		})
	}
}

// TestVaultWebhook_Unauthorized_Returns403 confirms all three handlers 403 a
// caller CanManageVault denies, and that the webhook service is never
// touched -- authorization must precede any service call.
func TestVaultWebhook_Unauthorized_Returns403(t *testing.T) {
	cases := []struct {
		name   string
		method string
		body   []byte
	}{
		{"PUT", http.MethodPut, []byte(`{"url":"https://hooks.example/rv"}`)},
		{"GET", http.MethodGet, nil},
		{"DELETE", http.MethodDelete, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &webhookStub{}
			policy := &mockAccessPolicyService{}
			policy.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(authzServices.AccessDenied, nil)
			// A webhook route always targets one vault, so CanManageVault
			// consults the vault-scoped check. The deny is stubbed on both:
			// a deny matches whatever its scope.
			policy.On("CheckVaultScopedAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(authzServices.AccessDenied, nil)
			api, _ := newWebhookTestAPI(t, stub, policy)

			w := doVaultRequestAs(api, model.RoleUser, tc.method, "/api/v1/vaults/prod/webhook", tc.body)

			assert.Equal(t, http.StatusForbidden, w.Code)
			assert.False(t, stub.called, "the webhook service must not be invoked when authorization denies the caller")
		})
	}
}

func TestDeleteVaultWebhook_Returns204(t *testing.T) {
	stub := &webhookStub{}
	api, _ := newWebhookTestAPI(t, stub, &mockAccessPolicyService{})

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/prod/webhook", nil)

	// deleteVault (api/vault.go) returns 204 on success; deleteVaultWebhook
	// mirrors that status.
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.True(t, stub.called)
}

func TestDeleteVaultWebhook_InternalErrorIsNotReportedAsSuccess(t *testing.T) {
	stub := &webhookStub{deleteErr: errors.New("connection refused")}
	api, _ := newWebhookTestAPI(t, stub, &mockAccessPolicyService{})

	w := doVaultRequest(api, http.MethodDelete, "/api/v1/vaults/prod/webhook", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestVaultWebhook_NilService_Returns500 confirms webhookSvc() reports a 500
// (via SetInternalError) instead of silently writing nothing when the
// container is non-nil but GetVaultWebhookService() itself returns nil. Before
// this fix, all three handlers returned early with no response written and no
// error set, which net/http turns into a misleading 200 with an empty body --
// worst for delete, which would report success for a delete that never ran.
func TestVaultWebhook_NilService_Returns500(t *testing.T) {
	cases := []struct {
		name   string
		method string
		body   []byte
	}{
		{"PUT", http.MethodPut, []byte(`{"url":"https://hooks.example/rv"}`)},
		{"GET", http.MethodGet, nil},
		{"DELETE", http.MethodDelete, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newVaultFakeRepo()
			id := uuid.New()
			repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
			repo.byID[id.String()] = repo.byName["prod"]

			vaultSvc := vaultServices.NewVaultService(repo, vaultNoopCascade{}, nil)
			cont := &vaultSvcTestContainer{
				vaultSvc: vaultSvc,
				// vaultWebhookSvc deliberately left nil: GetVaultWebhookService()
				// returns a nil interface even though the container itself is set.
				policySvc: &mockAccessPolicyService{},
				logger:    userTestLog(),
			}
			api := newVaultTestAPIWithContainer(cont)

			w := doVaultRequest(api, tc.method, "/api/v1/vaults/prod/webhook", tc.body)

			assert.Equal(t, http.StatusInternalServerError, w.Code,
				"a nil webhook service must surface as 500, never a bare 200")
		})
	}
}

// TestInitVault_WebhookRoutesOnVaultsRouter proves the routes are registered
// on BaseRoutes.Vaults, not BaseRoutes.VaultScoped. The {name} router is the
// vault-management tier; VaultScoped would put webhook config behind the
// data-plane role check, which is the wrong authorization model for it.
func TestInitVault_WebhookRoutesOnVaultsRouter(t *testing.T) {
	api, _ := newVaultTestAPI()

	routes, err := WalkRoutes(api.rootRouter)
	assert.NoError(t, err)

	found := map[string]bool{}
	for _, r := range routes {
		if r.Path == "/api/v1/vaults/{name}/webhook" {
			found[r.Method] = true
		}
		assert.NotEqual(t, "/api/v1/vaults/{vault_name}/webhook", r.Path,
			"webhook routes must not be registered on the vault-scoped ({vault_name}) router")
	}
	assert.True(t, found[http.MethodPut], "expected PUT /vaults/{name}/webhook")
	assert.True(t, found[http.MethodGet], "expected GET /vaults/{name}/webhook")
	assert.True(t, found[http.MethodDelete], "expected DELETE /vaults/{name}/webhook")
}
