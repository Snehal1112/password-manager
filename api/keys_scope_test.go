package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/repositories"
	keyservices "rocketvault/internal/services/keys"
	"rocketvault/model"
)

type scopeStubKeyService struct {
	keyservices.KeyService

	key        *model.Key
	keyErr     error
	list       []model.Key
	deleted    *model.Key
	deleteErr  error
	lastScope  model.Scope
	lastFilter repositories.KeyFilter
}

func (s *scopeStubKeyService) GetKey(_ context.Context, _ uuid.UUID, scope model.Scope) (*model.Key, error) {
	s.lastScope = scope
	return s.key, s.keyErr
}

func (s *scopeStubKeyService) ListKeys(_ context.Context, scope model.Scope, filter repositories.KeyFilter) ([]model.Key, error) {
	s.lastScope = scope
	s.lastFilter = filter
	return s.list, nil
}

func (s *scopeStubKeyService) DeleteKey(_ context.Context, _ uuid.UUID, scope model.Scope) (*model.Key, error) {
	s.lastScope = scope
	return s.deleted, s.deleteErr
}

// newKeyHandlerFixture wires a Context whose container returns svc as the key
// service. vaultName != "" marks a vault-scoped route.
func newKeyHandlerFixture(t *testing.T, svc keyservices.KeyService, keyID uuid.UUID,
	vaultName string) (*Context, *httptest.ResponseRecorder, *http.Request) {
	t.Helper()

	c := newKeyCtx(svc)
	c.Params.KeyID = keyID.String()

	return c, httptest.NewRecorder(), newScopeRequest(t, uuid.New(), vaultName)
}

func TestListKeysUsesTheScopeFromTheRoute(t *testing.T) {
	svc := &scopeStubKeyService{list: []model.Key{{ID: uuid.New(), Name: "k"}}}

	c, w, r := newKeyHandlerFixture(t, svc, uuid.New(), "team-a")
	listKeys(c, w, r)
	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind())

	c, w, r = newKeyHandlerFixture(t, svc, uuid.New(), "")
	listKeys(c, w, r)
	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeOwner, svc.lastScope.Kind())
}

func TestGetKeyUsesTheScopeFromTheRoute(t *testing.T) {
	keyID := uuid.New()
	svc := &scopeStubKeyService{key: &model.Key{ID: keyID, Name: "k", Type: model.KeyTypeRSA, Enabled: true}}

	c, w, r := newKeyHandlerFixture(t, svc, keyID, "team-a")
	getKey(c, w, r)
	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind())
}

func TestGetKeyMapsLifecycleDenialTo403AndNotFoundTo404(t *testing.T) {
	keyID := uuid.New()

	svc := &scopeStubKeyService{keyErr: keyservices.ErrKeyLifecycleDenied}
	c, w, r := newKeyHandlerFixture(t, svc, keyID, "team-a")
	getKey(c, w, r)
	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusForbidden, c.Err.StatusCode)

	svc = &scopeStubKeyService{keyErr: keyservices.ErrKeyNotFound}
	c, w, r = newKeyHandlerFixture(t, svc, keyID, "team-a")
	getKey(c, w, r)
	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
}
