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

// TestScopeZeroValueFailsClosed pins the highest-severity invariant in the
// refactor: an uninitialised Scope must never be mistaken for admin. This file
// is the only place a Scope composite literal is permitted.
func TestScopeZeroValueFailsClosed(t *testing.T) {
	var zero Scope

	assert.Equal(t, ScopeInvalid, zero.Kind())
	assert.Equal(t, ScopeKind(0), ScopeInvalid, "ScopeInvalid must be the zero value")
	assert.NotEqual(t, ScopeAdmin, zero.Kind(), "the zero value must not be admin")

	err := zero.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrScopeInvalid)
	assert.Equal(t, "invalid", zero.String())

	_, ok := zero.OwnerID()
	assert.False(t, ok)
}

func TestScopeStructLiteralWithoutKindFailsClosed(t *testing.T) {
	// A partially-populated literal — the exact shape a half-migrated call site
	// or a zero-valued mock return produces.
	s := Scope{vaultID: uuid.New(), actorID: uuid.New()}

	assert.Equal(t, ScopeInvalid, s.Kind())
	assert.ErrorIs(t, s.Validate(), ErrScopeInvalid)
}

func TestScopeValidateRejectsIncompleteConstructions(t *testing.T) {
	cases := []struct {
		name    string
		scope   Scope
		wantErr bool
	}{
		{"vault scope without vault id", NewVaultScope(uuid.Nil, uuid.New()), true},
		{"vault scope with vault id", NewVaultScope(uuid.New(), uuid.New()), false},
		{"owner scope without owner id", NewOwnerScope(uuid.New(), uuid.Nil), true},
		{"owner scope with owner id", NewOwnerScope(uuid.New(), uuid.New()), false},
		{"admin scope with nil actor", NewAdminScope(uuid.Nil), false},
		{"unknown kind", Scope{kind: ScopeKind(99)}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.scope.Validate()
			if c.wantErr {
				assert.ErrorIs(t, err, ErrScopeInvalid)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestScopeOwnerIDNeverOverloadsNil(t *testing.T) {
	// Regression pin for DeleteKeyInVault's documented "pass uuid.Nil to skip
	// the check". A vault or admin scope reports ok=false, not a Nil owner that
	// a caller could misread as "no check needed".
	for _, s := range []Scope{
		NewVaultScope(uuid.New(), uuid.New()),
		NewAdminScope(uuid.New()),
	} {
		id, ok := s.OwnerID()
		assert.False(t, ok, "scope %s must not report an owner", s)
		assert.Equal(t, uuid.Nil, id)
	}
}
