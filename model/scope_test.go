package model

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVaultScope(t *testing.T) {
	vaultID := uuid.New()
	actorID := uuid.New()
	s := NewVaultScope(vaultID, actorID)

	assert.Equal(t, ScopeVault, s.Kind())
	assert.Equal(t, vaultID, s.VaultID())
	assert.Equal(t, actorID, s.ActorID())
	assert.NoError(t, s.Validate())

	owner, ok := s.OwnerID()
	assert.False(t, ok, "a vault scope has no owner")
	assert.Equal(t, uuid.Nil, owner)
}

func TestNewOwnerScope(t *testing.T) {
	vaultID := uuid.New()
	ownerID := uuid.New()
	s := NewOwnerScope(vaultID, ownerID)

	assert.Equal(t, ScopeOwner, s.Kind())
	assert.Equal(t, vaultID, s.VaultID(), "vault id is advisory on an owner scope")
	assert.Equal(t, ownerID, s.ActorID(), "the owner is the actor")
	assert.NoError(t, s.Validate())

	owner, ok := s.OwnerID()
	require.True(t, ok)
	assert.Equal(t, ownerID, owner)
}

func TestNewAdminScope(t *testing.T) {
	actorID := uuid.New()
	s := NewAdminScope(actorID)

	assert.Equal(t, ScopeAdmin, s.Kind())
	assert.Equal(t, actorID, s.ActorID())
	assert.Equal(t, uuid.Nil, s.VaultID())
	assert.NoError(t, s.Validate())

	_, ok := s.OwnerID()
	assert.False(t, ok)
}

func TestScopeResolvedVaultIDFallsBackToDefault(t *testing.T) {
	vaultID := uuid.New()
	assert.Equal(t, vaultID, NewVaultScope(vaultID, uuid.New()).ResolvedVaultID())
	assert.Equal(t, uuid.MustParse(DefaultVaultID), NewAdminScope(uuid.New()).ResolvedVaultID())
	assert.Equal(t, uuid.MustParse(DefaultVaultID), NewOwnerScope(uuid.Nil, uuid.New()).ResolvedVaultID())
}

func TestScopeStringNeverLeaksSecretMaterial(t *testing.T) {
	vaultID := uuid.New()
	ownerID := uuid.New()
	actorID := uuid.New()

	assert.Equal(t, "vault("+vaultID.String()+")", NewVaultScope(vaultID, actorID).String())
	assert.Equal(t, "owner("+ownerID.String()+")", NewOwnerScope(vaultID, ownerID).String())
	assert.Equal(t, "admin("+actorID.String()+")", NewAdminScope(actorID).String())
}
