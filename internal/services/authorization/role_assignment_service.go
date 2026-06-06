package authorization

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

var (
	ErrInvalidRole        = errors.New("invalid role")
	ErrPrincipalNotFound  = errors.New("principal not found")
	ErrAssignmentNotFound = errors.New("role assignment not found")
)

// roleAssignmentRepo is the subset of the role-assignment repository the service needs.
type roleAssignmentRepo interface {
	Create(ctx context.Context, ra *model.RoleAssignment) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.RoleAssignment, error)
	ListByVault(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error)
	FindByTuple(ctx context.Context, principalID uuid.UUID, role string, vaultID uuid.UUID) (*model.RoleAssignment, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// policyWriter is the subset of the access-policy repository the service needs.
type policyWriter interface {
	Create(ctx context.Context, p *model.AccessPolicy) error
	DeleteByAssignmentID(ctx context.Context, assignmentID uuid.UUID) error
}

// userLookup resolves a username to a user.
type userLookup interface {
	ReadByUsername(ctx context.Context, username string) (model.User, error)
}

// AssignRoleInput carries the resolved request to AssignRole.
type AssignRoleInput struct {
	Principal     string
	PrincipalType model.PrincipalType
	Role          string
	VaultID       uuid.UUID
	CreatedBy     uuid.UUID
}

// RoleAssignmentService grants, revokes, and lists vault-scoped role assignments.
type RoleAssignmentService interface {
	AssignRole(ctx context.Context, in AssignRoleInput) (*model.RoleAssignment, error)
	RevokeAssignment(ctx context.Context, assignmentID, vaultID uuid.UUID) error
	ListAssignments(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error)
}

type roleAssignmentService struct {
	roleRepo   roleAssignmentRepo
	policyRepo policyWriter
	users      userLookup
	log        *logging.Logger
}

// NewRoleAssignmentService constructs the service. The logger is optional and may be nil.
func NewRoleAssignmentService(rr roleAssignmentRepo, pr policyWriter, ul userLookup, log *logging.Logger) RoleAssignmentService {
	return &roleAssignmentService{roleRepo: rr, policyRepo: pr, users: ul, log: log}
}

func (s *roleAssignmentService) AssignRole(ctx context.Context, in AssignRoleInput) (*model.RoleAssignment, error) {
	if !IsValidRole(in.Role) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRole, in.Role)
	}
	pType := in.PrincipalType
	if pType == "" {
		pType = model.PrincipalTypeUser
	}

	principalID, err := s.resolvePrincipal(ctx, in.Principal)
	if err != nil {
		return nil, err
	}

	existing, err := s.roleRepo.FindByTuple(ctx, principalID, in.Role, in.VaultID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return existing, nil
	}

	assignmentID := uuid.New()
	ra := &model.RoleAssignment{
		ID:            assignmentID,
		PrincipalID:   principalID,
		PrincipalType: pType,
		Role:          in.Role,
		VaultID:       in.VaultID,
		CreatedBy:     in.CreatedBy,
	}
	if err := s.roleRepo.Create(ctx, ra); err != nil {
		return nil, fmt.Errorf("create assignment: %w", err)
	}

	policies, err := ExpandRole(in.Role, principalID, pType, in.VaultID, assignmentID)
	if err != nil {
		if delErr := s.roleRepo.Delete(ctx, assignmentID); delErr != nil && s.log != nil {
			s.log.LogAuditError("", "assign_role", "rollback", fmt.Sprintf("rollback: failed to delete assignment %s", assignmentID), delErr)
		}
		return nil, err
	}
	for _, p := range policies {
		if err := s.policyRepo.Create(ctx, p); err != nil {
			if delErr := s.policyRepo.DeleteByAssignmentID(ctx, assignmentID); delErr != nil && s.log != nil {
				s.log.LogAuditError("", "assign_role", "rollback", fmt.Sprintf("rollback: failed to delete policies for assignment %s", assignmentID), delErr)
			}
			if delErr := s.roleRepo.Delete(ctx, assignmentID); delErr != nil && s.log != nil {
				s.log.LogAuditError("", "assign_role", "rollback", fmt.Sprintf("rollback: failed to delete assignment %s", assignmentID), delErr)
			}
			return nil, fmt.Errorf("expand role policies: %w", err)
		}
	}
	return ra, nil
}

func (s *roleAssignmentService) RevokeAssignment(ctx context.Context, assignmentID, vaultID uuid.UUID) error {
	ra, err := s.roleRepo.GetByID(ctx, assignmentID)
	if err != nil {
		return ErrAssignmentNotFound
	}
	if ra.VaultID != vaultID {
		return ErrAssignmentNotFound
	}
	if err := s.policyRepo.DeleteByAssignmentID(ctx, assignmentID); err != nil {
		return fmt.Errorf("delete policies: %w", err)
	}
	if err := s.roleRepo.Delete(ctx, assignmentID); err != nil {
		return fmt.Errorf("delete assignment: %w", err)
	}
	return nil
}

func (s *roleAssignmentService) ListAssignments(ctx context.Context, vaultID uuid.UUID) ([]*model.RoleAssignment, error) {
	return s.roleRepo.ListByVault(ctx, vaultID)
}

// resolvePrincipal accepts a UUID string or a username and returns the principal UUID.
func (s *roleAssignmentService) resolvePrincipal(ctx context.Context, principal string) (uuid.UUID, error) {
	if id, err := uuid.Parse(principal); err == nil {
		return id, nil
	}
	u, err := s.users.ReadByUsername(ctx, principal)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: %s", ErrPrincipalNotFound, principal)
	}
	return u.ID, nil
}
