package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// newScopeRequest builds a request carrying a resolved vault id and, when
// vaultName is non-empty, the vault_name route variable that marks a
// vault-scoped route.
func newScopeRequest(t *testing.T, vaultID uuid.UUID, vaultName string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/"+uuid.NewString(), nil)
	r = r.WithContext(context.WithValue(r.Context(), common.VaultIDKey, vaultID.String()))
	if vaultName != "" {
		r = mux.SetURLVars(r, map[string]string{"vault_name": vaultName})
	}
	return r
}

func newScopeContext(userID uuid.UUID) *Context {
	return &Context{Claims: RequestClaims{UserID: userID.String()}}
}

func TestScopeFromRequestVaultScopedRouteYieldsVaultScope(t *testing.T) {
	vaultID, userID := uuid.New(), uuid.New()
	c := newScopeContext(userID)

	scope, ok := scopeFromRequest(c, newScopeRequest(t, vaultID, "team-a"))
	require.True(t, ok)
	assert.Equal(t, model.ScopeVault, scope.Kind())
	assert.Equal(t, vaultID, scope.VaultID())
	assert.Equal(t, userID, scope.ActorID(), "the actor travels for audit")
	assert.NoError(t, scope.Validate())
}

// TestScopeFromRequestFlatRouteYieldsVaultScope pins the fix for the
// 2026-08-16 pentest finding H2. A legacy flat route must resolve to a vault
// scope carrying the vault the request was authorized against. An owner scope
// here filtered on user_id with no vault term at all, so a caller could read
// and write their own resources in any other vault.
func TestScopeFromRequestFlatRouteYieldsVaultScope(t *testing.T) {
	vaultID, userID := uuid.New(), uuid.New()
	c := newScopeContext(userID)

	scope, ok := scopeFromRequest(c, newScopeRequest(t, vaultID, ""))
	require.True(t, ok)
	assert.Equal(t, model.ScopeVault, scope.Kind())
	assert.Equal(t, vaultID, scope.VaultID(), "a flat route targets the vault it was authorized against")
	assert.Equal(t, userID, scope.ActorID(), "the actor travels for audit")

	_, isOwnerScoped := scope.OwnerID()
	assert.False(t, isOwnerScoped, "ownership is never an access predicate on the data plane")
	assert.NoError(t, scope.Validate())
}

// TestScopeHelpersFailClosedWithoutAUserClaim asserts scopeFromRequest — the
// only scope constructor left on the data plane since ownerScopeFromRequest
// was deleted in P2 — sets c.Err and returns false rather than proceeding
// with an invalid scope when the caller's identity cannot be determined.
func TestScopeHelpersFailClosedWithoutAUserClaim(t *testing.T) {
	c := &Context{Claims: RequestClaims{}}
	r := newScopeRequest(t, uuid.New(), "team-a")

	scope, ok := scopeFromRequest(c, r)
	assert.False(t, ok)
	assert.Equal(t, model.ScopeInvalid, scope.Kind())
	require.NotNil(t, c.Err)
}

func TestWriteSecretErrorMapsEachCase(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		statusCode int
	}{
		{"not found", secrets.ErrSecretNotFound, http.StatusNotFound},
		{"wrapped not found", errors.Join(secrets.ErrSecretNotFound, errors.New("ctx")), http.StatusNotFound},
		{"lifecycle denied", secrets.ErrSecretLifecycleDenied, http.StatusForbidden},
		{"anything else", errors.New("boom"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Context{}
			writeSecretError(c, tc.err)
			require.NotNil(t, c.Err)
			assert.Equal(t, tc.statusCode, c.Err.StatusCode)
		})
	}
}
