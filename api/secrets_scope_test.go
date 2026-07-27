package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// scopeStubSecretService embeds secrets.SecretService so only the methods
// under test need bodies; the embedded nil interface panics loudly if a
// handler calls anything else, which is the desired signal.
type scopeStubSecretService struct {
	secrets.SecretService

	secret            *model.Secret
	secretErr         error
	list              []model.Secret
	listErr           error
	versionsScopedErr error
	lastScope         model.Scope
}

func (s *scopeStubSecretService) GetSecretScoped(_ context.Context, _ uuid.UUID, scope model.Scope) (*model.Secret, error) {
	s.lastScope = scope
	return s.secret, s.secretErr
}

func (s *scopeStubSecretService) ListSecretsScoped(_ context.Context, scope model.Scope, _ []string) ([]model.Secret, error) {
	s.lastScope = scope
	return s.list, s.listErr
}

func (s *scopeStubSecretService) DeleteSecretScoped(_ context.Context, _ uuid.UUID, scope model.Scope) error {
	s.lastScope = scope
	return nil
}

func (s *scopeStubSecretService) GetSecretVersionsScoped(_ context.Context, _ uuid.UUID, scope model.Scope) ([]model.SecretVersion, error) {
	s.lastScope = scope
	return nil, s.versionsScopedErr
}

// newSecretHandlerFixture wires a Context whose service container returns svc,
// reusing newSecretCtx from api/secrets_handlers_test.go:324 rather than
// introducing a second wiring style. vaultName != "" marks a vault-scoped route.
func newSecretHandlerFixture(t *testing.T, svc secrets.SecretService, secretID uuid.UUID,
	vaultName string) (*Context, *httptest.ResponseRecorder, *http.Request) {
	t.Helper()

	c := newSecretCtx(svc)
	c.Params.SecretID = secretID.String()

	return c, httptest.NewRecorder(), newScopeRequest(t, uuid.New(), vaultName)
}

// TestListSecretVersionsWrongVaultReturns404 pins the deliberate 500 -> 404
// correction from spec §1: listSecretVersionsHandler returned 500 for a
// wrong-vault lookup while getSecretVersionHandler and
// getLatestSecretVersionHandler returned 404.
func TestListSecretVersionsWrongVaultReturns404(t *testing.T) {
	secretID := uuid.New()
	svc := &scopeStubSecretService{
		versionsScopedErr: secrets.ErrSecretNotFound,
	}
	c, w, r := newSecretHandlerFixture(t, svc, secretID, "team-a")

	listSecretVersionsHandler(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
}

func TestGetSecretUsesTheScopeFromTheRoute(t *testing.T) {
	secretID := uuid.New()
	svc := &scopeStubSecretService{
		secret: &model.Secret{ID: secretID, Name: "s", Value: "v", Enabled: true},
	}

	c, w, r := newSecretHandlerFixture(t, svc, secretID, "team-a")
	getSecret(c, w, r)
	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind())

	c, w, r = newSecretHandlerFixture(t, svc, secretID, "")
	getSecret(c, w, r)
	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeOwner, svc.lastScope.Kind())
}

func TestGetSecretMapsLifecycleDenialTo403(t *testing.T) {
	secretID := uuid.New()
	svc := &scopeStubSecretService{secretErr: secrets.ErrSecretLifecycleDenied}
	c, w, r := newSecretHandlerFixture(t, svc, secretID, "team-a")

	getSecret(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusForbidden, c.Err.StatusCode)
}

func TestDeleteSecretAlwaysUsesAVaultScope(t *testing.T) {
	secretID := uuid.New()
	svc := &scopeStubSecretService{}

	// deleteSecret was already vault-scoped on both route shapes before the
	// refactor; that must not change.
	c, w, r := newSecretHandlerFixture(t, svc, secretID, "")
	r.Method = http.MethodDelete
	deleteSecret(c, w, r)
	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind())
}

func TestListSecretsUsesTheScopeFromTheRoute(t *testing.T) {
	svc := &scopeStubSecretService{list: []model.Secret{{ID: uuid.New(), Name: "a"}}}

	c, w, r := newSecretHandlerFixture(t, svc, uuid.New(), "team-a")
	listSecrets(c, w, r)
	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind())
	assert.Equal(t, http.StatusOK, w.Code)
}
