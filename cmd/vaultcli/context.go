package vaultcli

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// CtxKey binds a context key to the type stored under it. Looking a value up
// through one of the vars below cannot assert the wrong type, and cannot
// silently skip the "is it there?" check: the only way to read the value is
// through From, which always returns an error when it is absent.
//
// This replaces hand-written `ctx.Value(common.LogKey).(*logging.Logger)`
// assertions. Those were written without the comma-ok form in 22 files, so a
// context missing the logger panicked rather than erroring -- reachable as
// soon as a command runs under remotePersistentPreRun (cmd/root.go), which
// stashes no logger at all.
type CtxKey[T any] struct {
	key  any
	what string
}

// From reads the value stored under k, returning a uniform error when it is
// absent or of the wrong type.
func (k CtxKey[T]) From(ctx context.Context) (T, error) {
	v, ok := ctx.Value(k.key).(T)
	if !ok {
		var zero T
		return zero, fmt.Errorf("%s not available in context", k.what)
	}
	return v, nil
}

// With returns a context carrying v under k. Pre-runs use this so the writing
// and reading sides cannot disagree about the value's type.
func (k CtxKey[T]) With(ctx context.Context, v T) context.Context {
	return context.WithValue(ctx, k.key, v)
}

// The context values every CLI command reads. The key and the type travel
// together, so adding a new one here is the only place the pairing is stated.
var (
	CtxClaims    = CtxKey[*model.Claims]{common.ClaimsKey, "authentication claims"}
	CtxContainer = CtxKey[container.ServiceContainerInterface]{common.ServiceContainerKey, "service container"}
	CtxFormatter = CtxKey[formatter.Formatter]{common.OutputFormatterKey, "output formatter"}
	CtxLogger    = CtxKey[*logging.Logger]{common.LogKey, "logger"}
	CtxUserID    = CtxKey[uuid.UUID]{common.UserIDKey, "user ID"}
	CtxToken     = CtxKey[string]{common.TokenKey, "session token"}
)

// CallerIdentity extracts the acting principal's account roles and user ID
// from the CLI's authenticated context, populated by persistentPreRun in
// cmd/root.go. An error here means a command reached the service layer
// without prior authentication -- a wiring bug, not a permission denial.
//
// This is the single copy of what cmd/vaults, cmd/vault-access,
// cmd/vault-webhook and cmd/vault-provisioning each defined verbatim.
func CallerIdentity(ctx context.Context) (roles []string, principalID uuid.UUID, err error) {
	claims, err := CtxClaims.From(ctx)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("authenticated claims not available in context")
	}
	if claims == nil {
		return nil, uuid.Nil, fmt.Errorf("authenticated claims not available in context")
	}
	return claims.Roles, claims.UserID, nil
}
