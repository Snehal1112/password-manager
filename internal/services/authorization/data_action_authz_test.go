package authorization

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"rocketvault/model"
)

// fakeRoleAssignmentService is a minimal test double for RoleAssignmentService,
// returning a fixed decision/error for HasDataAction. The remaining interface
// methods are no-ops; no test in this file exercises them.
type fakeRoleAssignmentService struct {
	hasAction bool
	err       error
}

func (f *fakeRoleAssignmentService) AssignRole(ctx context.Context, in AssignRoleInput) (*model.RoleAssignment, error) {
	return nil, nil
}

func (f *fakeRoleAssignmentService) RevokeAssignment(ctx context.Context, assignmentID, vaultID uuid.UUID) error {
	return nil
}

func (f *fakeRoleAssignmentService) ListAssignments(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	return nil, nil
}

func (f *fakeRoleAssignmentService) HasDataAction(ctx context.Context, principalID, vaultID uuid.UUID, action model.DataAction) (bool, error) {
	return f.hasAction, f.err
}

func TestRequireDataAction_Grants(t *testing.T) {
	roles := &fakeRoleAssignmentService{hasAction: true}
	err := RequireDataAction(context.Background(), roles, uuid.New(), uuid.New(), model.ActionSecretsGet)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestRequireDataAction_Denies(t *testing.T) {
	roles := &fakeRoleAssignmentService{hasAction: false}
	err := RequireDataAction(context.Background(), roles, uuid.New(), uuid.New(), model.ActionSecretsGet)
	if err == nil {
		t.Fatal("expected a forbidden error, got nil")
	}
}

func TestRequireDataAction_PropagatesLookupError(t *testing.T) {
	wantErr := errors.New("db exploded")
	roles := &fakeRoleAssignmentService{err: wantErr}
	err := RequireDataAction(context.Background(), roles, uuid.New(), uuid.New(), model.ActionSecretsGet)
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("expected error wrapping %v, got %v", wantErr, err)
	}
}

func TestRequireDataAction_DenyNotConflatedWithLookupError(t *testing.T) {
	// A plain deny (false, nil) must not satisfy errors.Is against some
	// sentinel lookup error — they're different failure classes with
	// different messages, per the design's error-handling section.
	roles := &fakeRoleAssignmentService{hasAction: false}
	err := RequireDataAction(context.Background(), roles, uuid.New(), uuid.New(), model.ActionKeysWrap)
	if errors.Is(err, errors.New("db exploded")) {
		t.Fatal("a plain deny must not resemble a lookup error")
	}
}
