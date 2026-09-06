package vaultcli

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/common"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

func TestCtxKey_RoundTrip(t *testing.T) {
	t.Parallel()

	claims := &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}
	ctx := CtxClaims.With(context.Background(), claims)

	got, err := CtxClaims.From(ctx)
	require.NoError(t, err)
	assert.Same(t, claims, got)
}

// The whole point of the type: a missing value is an error, never a panic.
// 22 files previously wrote ctx.Value(common.LogKey).(*logging.Logger) with
// no comma-ok, which panics on exactly this context.
func TestCtxKey_Missing_ErrorsRatherThanPanics(t *testing.T) {
	t.Parallel()

	assert.NotPanics(t, func() {
		_, err := CtxLogger.From(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger not available in context")
	})
}

// A value of the wrong type under the right key is treated as absent, not
// returned as a zero value that a caller might use.
func TestCtxKey_WrongType_Errors(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(context.Background(), common.LogKey, "not a logger")

	_, err := CtxLogger.From(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not available in context")
}

func TestCtxKey_EachKeyReadsItsOwnValue(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	log := &logging.Logger{Logger: logrus.New()}

	ctx := CtxUserID.With(context.Background(), userID)
	ctx = CtxLogger.With(ctx, log)
	ctx = CtxToken.With(ctx, "tok")

	gotID, err := CtxUserID.From(ctx)
	require.NoError(t, err)
	assert.Equal(t, userID, gotID)

	gotLog, err := CtxLogger.From(ctx)
	require.NoError(t, err)
	assert.Same(t, log, gotLog)

	gotTok, err := CtxToken.From(ctx)
	require.NoError(t, err)
	assert.Equal(t, "tok", gotTok)

	// A key that was never written stays absent.
	_, err = CtxClaims.From(ctx)
	assert.Error(t, err)
}

func TestCallerIdentity(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	roles := []string{model.RoleAdmin, model.RoleCryptoManager}
	ctx := CtxClaims.With(context.Background(), &model.Claims{UserID: userID, Roles: roles})

	gotRoles, gotID, err := CallerIdentity(ctx)
	require.NoError(t, err)
	assert.Equal(t, roles, gotRoles)
	assert.Equal(t, userID, gotID)
}

func TestCallerIdentity_NoClaims(t *testing.T) {
	t.Parallel()

	_, id, err := CallerIdentity(context.Background())
	require.Error(t, err)
	assert.Equal(t, uuid.Nil, id)
	assert.Contains(t, err.Error(), "authenticated claims not available in context")
}

// A nil *model.Claims stored under the key satisfies the type assertion, so
// the nil check has to be explicit -- every copy of the old callerIdentity
// had one, and dropping it would nil-panic on claims.Roles.
func TestCallerIdentity_NilClaims(t *testing.T) {
	t.Parallel()

	ctx := CtxClaims.With(context.Background(), (*model.Claims)(nil))

	_, id, err := CallerIdentity(ctx)
	require.Error(t, err)
	assert.Equal(t, uuid.Nil, id)
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

// Caller deliberately stops short of authorizing, so commands can validate
// their flags first. The safety net is that the Session it returns carries a
// zero model.Scope, whose kind is ScopeInvalid -- every repository rejects it.
// A command that forgets Authorize therefore reads nothing, rather than
// reading with an unchecked vault id.
func TestCaller_LeavesScopeInvalidUntilAuthorize(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{Use: "test"}
	cmd.SetContext(CtxLogger.With(
		CtxClaims.With(context.Background(), &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleAdmin}}),
		&logging.Logger{Logger: logrus.New()},
	))

	s, err := Caller(cmd, Op{Audit: "test_op", Action: model.ActionKeysRead, Policy: model.OpGet})
	require.NoError(t, err)

	assert.Equal(t, uuid.Nil, s.VaultID, "Caller must not resolve a vault")
	assert.Error(t, s.Scope.Validate(), "an un-authorized Session's scope must fail closed")
}

// An Op with no data action is a wiring mistake: it would produce a Session
// that authorizes against nothing. Refuse it loudly at construction.
func TestCaller_RequiresADataAction(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{Use: "test"}
	cmd.SetContext(context.Background())

	_, err := Caller(cmd, Op{Audit: "test_op"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Op.Action is required")
}

func TestCaller_RoleGate(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{Use: "test"}
	cmd.SetContext(CtxLogger.With(
		CtxClaims.With(context.Background(), &model.Claims{UserID: uuid.New(), Roles: []string{model.RoleUser}}),
		&logging.Logger{Logger: logrus.New()},
	))

	_, err := Caller(cmd, Op{
		Audit: "create_key", Action: model.ActionKeysCreate, Policy: model.OpCreate,
		Roles: []string{model.RoleAdmin, model.RoleCryptoManager},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden: requires admin or crypto_manager role")
}

func TestCaller_NoClaims(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{Use: "test"}
	cmd.SetContext(context.Background())

	_, err := Caller(cmd, Op{Audit: "get_key", Action: model.ActionKeysRead, Policy: model.OpGet})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unauthorized: missing authentication claims")
}

func TestHumanRoles(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "admin role", humanRoles([]string{"admin"}))
	assert.Equal(t, "admin or crypto_manager role", humanRoles([]string{"admin", "crypto_manager"}))
	assert.Equal(t, "a, b or c role", humanRoles([]string{"a", "b", "c"}))
}
