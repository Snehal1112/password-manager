package repositories

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/model"
)

// TestScopePredicateBindArity asserts every scope kind produces exactly as many
// "?" placeholders as bind arguments. A mismatch is a SQL injection or a
// runtime "sql: expected N arguments" panic waiting to happen.
func TestScopePredicateBindArity(t *testing.T) {
	cases := []struct {
		name  string
		scope model.Scope
	}{
		{"vault", model.NewVaultScope(uuid.New(), uuid.New())},
		{"owner", model.NewOwnerScope(uuid.New(), uuid.New())},
		{"admin", model.NewAdminScope(uuid.New())},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fragment, args, err := scopePredicate(c.scope)
			require.NoError(t, err)
			assert.Equal(t, strings.Count(fragment, "?"), len(args),
				"fragment %q has %d placeholders but %d bind args", fragment, strings.Count(fragment, "?"), len(args))
		})
	}
}

func TestScopePredicateFragments(t *testing.T) {
	vaultID := uuid.New()
	ownerID := uuid.New()

	fragment, args, err := scopePredicate(model.NewVaultScope(vaultID, uuid.New()))
	require.NoError(t, err)
	assert.Equal(t, "vault_id = ?", fragment)
	assert.Equal(t, []any{vaultID.String()}, args)

	fragment, args, err = scopePredicate(model.NewOwnerScope(uuid.New(), ownerID))
	require.NoError(t, err)
	assert.Equal(t, "user_id = ?", fragment)
	assert.Equal(t, []any{ownerID.String()}, args)

	fragment, args, err = scopePredicate(model.NewAdminScope(uuid.New()))
	require.NoError(t, err)
	assert.Equal(t, "1 = 1", fragment)
	assert.Empty(t, args)
}

func TestScopePredicateRejectsInvalidScope(t *testing.T) {
	var zero model.Scope

	fragment, args, err := scopePredicate(zero)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidScope)
	assert.Empty(t, fragment, "no fragment may be returned for an invalid scope")
	assert.Nil(t, args)
}

func TestScopePredicateRejectsIncompleteVaultScope(t *testing.T) {
	_, _, err := scopePredicate(model.NewVaultScope(uuid.Nil, uuid.New()))
	assert.ErrorIs(t, err, ErrInvalidScope)
}

// TestScopePredicateNeverInterpolates guards the rule that no caller-supplied
// value is ever concatenated into the fragment.
func TestScopePredicateNeverInterpolates(t *testing.T) {
	vaultID := uuid.New()
	fragment, _, err := scopePredicate(model.NewVaultScope(vaultID, uuid.New()))
	require.NoError(t, err)
	assert.NotContains(t, fragment, vaultID.String())
}
