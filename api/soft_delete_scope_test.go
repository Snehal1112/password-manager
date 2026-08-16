package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
	"rocketvault/model"
)

type scopeStubSoftDeleteService struct {
	secrets.SecretService

	deleted      []model.Secret
	recoverErr   error
	purgeErr     error
	lastScope    model.Scope
	recoverCalls int
	purgeCalls   int
}

func (s *scopeStubSoftDeleteService) ListDeletedSecrets(_ context.Context, scope model.Scope) ([]model.Secret, error) {
	s.lastScope = scope
	return s.deleted, nil
}

func (s *scopeStubSoftDeleteService) RecoverSecret(_ context.Context, _ uuid.UUID, scope model.Scope) error {
	s.lastScope = scope
	s.recoverCalls++
	return s.recoverErr
}

func (s *scopeStubSoftDeleteService) PurgeSecret(_ context.Context, _ uuid.UUID, scope model.Scope) error {
	s.lastScope = scope
	s.purgeCalls++
	return s.purgeErr
}

func TestRecoverSecretPassesTheScopeAndDropsThePreCheck(t *testing.T) {
	svc := &scopeStubSoftDeleteService{}
	c, w, r := newSecretHandlerFixture(t, svc, uuid.New(), "team-a")

	recoverSecret(c, w, r)

	require.Nil(t, c.Err)
	assert.Equal(t, 1, svc.recoverCalls, "the service performs the authorization; no handler pre-check")
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind())
}

func TestRecoverSecretOutOfScopeReturns404(t *testing.T) {
	svc := &scopeStubSoftDeleteService{recoverErr: secrets.ErrSecretNotFound}
	c, w, r := newSecretHandlerFixture(t, svc, uuid.New(), "team-a")

	recoverSecret(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
}

func TestPurgeSecretOutOfScopeReturns404(t *testing.T) {
	svc := &scopeStubSoftDeleteService{purgeErr: secrets.ErrSecretNotFound}
	c, w, r := newSecretHandlerFixture(t, svc, uuid.New(), "")

	purgeSecret(c, w, r)

	require.NotNil(t, c.Err)
	assert.Equal(t, http.StatusNotFound, c.Err.StatusCode)
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind(), "flat routes are vault-scoped to the default vault")
}

func TestListDeletedSecretsUsesAVaultScope(t *testing.T) {
	svc := &scopeStubSoftDeleteService{deleted: []model.Secret{{ID: uuid.New(), Name: "gone"}}}
	c, w, r := newSecretHandlerFixture(t, svc, uuid.New(), "team-a")

	listDeletedSecrets(c, w, r)

	require.Nil(t, c.Err)
	assert.Equal(t, model.ScopeVault, svc.lastScope.Kind())
}
