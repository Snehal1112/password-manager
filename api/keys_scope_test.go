package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
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

	// policyRepo backs the key-rotation-policy methods below. Tests that only
	// exercise the key-access denial path (keyErr set) never reach it.
	policyRepo repositories.KeyRotationPolicyRepositoryInterface
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

// GetKeyRotationPolicy, UpsertKeyRotationPolicy and DeleteKeyRotationPolicy
// mirror the real KeyService: verify key access first (recording the scope
// via GetKey above), then delegate to policyRepo.

func (s *scopeStubKeyService) GetKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) (*model.KeyRotationPolicy, error) {
	if _, err := s.GetKey(ctx, keyID, scope); err != nil {
		return nil, err
	}
	return s.policyRepo.GetByKeyIDAny(ctx, keyID)
}

func (s *scopeStubKeyService) UpsertKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope, req model.UpsertKeyRotationPolicyRequest) (*model.KeyRotationPolicy, error) {
	if _, err := s.GetKey(ctx, keyID, scope); err != nil {
		return nil, err
	}
	now := time.Now()
	policy := &model.KeyRotationPolicy{
		ID:                     uuid.New(),
		KeyID:                  keyID,
		UserID:                 scope.ActorID(),
		RotateAfterDays:        req.RotateAfterDays,
		NotifyBeforeExpiryDays: req.NotifyBeforeExpiryDays,
		ExpiryDays:             req.ExpiryDays,
		Enabled:                req.Enabled,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if err := s.policyRepo.Upsert(ctx, policy); err != nil {
		return nil, err
	}
	return s.policyRepo.GetByKeyIDAny(ctx, keyID)
}

func (s *scopeStubKeyService) DeleteKeyRotationPolicy(ctx context.Context, keyID uuid.UUID, scope model.Scope) error {
	if _, err := s.GetKey(ctx, keyID, scope); err != nil {
		return err
	}
	return s.policyRepo.DeleteByKeyIDAny(ctx, keyID)
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
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind(), "flat routes are vault-scoped to the default vault")
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

// TestKeyRotationPolicyHandlers_LifecycleDeniedMapsTo404 pins the same fix
// Task 4 shipped for the certificate-policy handlers, one domain over: routing
// the rotation-policy handlers through KeyService's new
// GetKeyRotationPolicy/UpsertKeyRotationPolicy/DeleteKeyRotationPolicy methods
// (which propagate whatever GetKey returns, collapsed into the same error
// return as the policy-repo call) would make writeKeyError's
// ErrKeyLifecycleDenied->403 mapping reachable here if the handlers used it.
// They don't -- they check errors.Is against ErrKeyNotFound/
// ErrKeyLifecycleDenied directly. The pre-refactor handlers always mapped ANY
// key-check failure to a blanket 404 "key", never distinguishing
// lifecycle-denied from not-found. All three handlers must keep returning
// 404, not 403, for a disabled/expired key.
func TestKeyRotationPolicyHandlers_LifecycleDeniedMapsTo404(t *testing.T) {
	keyID := uuid.New()

	t.Run("get", func(t *testing.T) {
		svc := &scopeStubKeyService{keyErr: keyservices.ErrKeyLifecycleDenied}
		c, w, r := newKeyHandlerFixture(t, svc, keyID, "team-a")
		getKeyRotationPolicy(c, w, r)
		require.NotNil(t, c.Err)
		assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
	})

	t.Run("upsert", func(t *testing.T) {
		svc := &scopeStubKeyService{keyErr: keyservices.ErrKeyLifecycleDenied}
		c := newKeyCtx(svc)
		c.Params.KeyID = keyID.String()
		w := httptest.NewRecorder()
		body := []byte(`{"rotate_after_days":90,"enabled":true}`)
		r := httptest.NewRequest(http.MethodPut, "/api/v1/vaults/team-a/keys/"+keyID.String()+"/rotationpolicy", bytes.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, uuid.New().String()))
		r = mux.SetURLVars(r, map[string]string{"vault_name": "team-a"})

		upsertKeyRotationPolicy(c, w, r)
		require.NotNil(t, c.Err)
		assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
	})

	t.Run("delete", func(t *testing.T) {
		svc := &scopeStubKeyService{keyErr: keyservices.ErrKeyLifecycleDenied}
		c, w, r := newKeyHandlerFixture(t, svc, keyID, "team-a")
		deleteKeyRotationPolicy(c, w, r)
		require.NotNil(t, c.Err)
		assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
	})
}
