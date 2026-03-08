// Package users provides user management services for the password manager.
// It handles user creation, updates, and management workflows while
// coordinating with authentication services and repositories.
package users

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/domain"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	authService "rocketvault/internal/services/auth"
)

// CreateUserRequest represents a request to create a new user.
type CreateUserRequest struct {
	Username string
	Password string
	Role     string
}

// CreateUserResult represents the result of creating a new user.
type CreateUserResult struct {
	UserID     uuid.UUID
	Username   string
	Role       string
	TOTPSecret string // QR code URL for user setup
	CreatedAt  time.Time
}

// UpdateUserRequest represents a request to update an existing user.
type UpdateUserRequest struct {
	UserID   uuid.UUID
	Username *string // Optional - nil means no change
	Password *string // Optional - nil means no change
	Role     *string // Optional - nil means no change
}

// UserService handles user management operations.
// It orchestrates user creation and updates by coordinating
// with authentication services and user repositories.
type UserService interface {
	CreateUser(ctx context.Context, req CreateUserRequest) (*CreateUserResult, error)
	UpdateUser(ctx context.Context, req UpdateUserRequest) error
	GetUser(ctx context.Context, userID uuid.UUID) (*domain.User, error)
	GetUserByUsername(ctx context.Context, username string) (*domain.User, error)
	ListUsers(ctx context.Context) ([]domain.User, error)
	DeleteUser(ctx context.Context, userID uuid.UUID) error
	ValidateBootstrapToken(ctx context.Context, token string) (bool, error)
	InvalidateBootstrapToken(ctx context.Context, token string) error
}

// userService implements UserService by coordinating authentication
// services and user repository operations.
type userService struct {
	userRepo        repositories.UserRepositoryInterface
	passwordService authService.PasswordService
	totpService     authService.TOTPService
	logger          *logging.Logger
}

// UserServiceConfig holds the dependencies for user service.
type UserServiceConfig struct {
	UserRepository  repositories.UserRepositoryInterface
	PasswordService authService.PasswordService
	TOTPService     authService.TOTPService
	Logger          *logging.Logger
}

// NewUserService creates a new UserService with the provided dependencies.
// It orchestrates user management operations by coordinating different services.
//
// Parameters:
//
//	config: Configuration containing all required dependencies.
//
// Returns:
//
//	A UserService implementation for user management operations.
func NewUserService(config UserServiceConfig) UserService {
	return &userService{
		userRepo:        config.UserRepository,
		passwordService: config.PasswordService,
		totpService:     config.TOTPService,
		logger:          config.Logger,
	}
}

// CreateUser creates a new user with the provided information.
// It orchestrates password hashing, TOTP secret generation,
// and user storage while maintaining proper separation of concerns.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The user creation request with username, password, and role.
//
// Returns:
//
//	The created user information including TOTP setup details, or an error if creation fails.
func (s *userService) CreateUser(ctx context.Context, req CreateUserRequest) (*CreateUserResult, error) {
	logrus.WithFields(logrus.Fields{
		"username": req.Username,
		"role":     req.Role,
	}).Info("Creating new user")

	// Hash password using password service
	hashedPassword, err := s.passwordService.HashPassword(req.Password)
	if err != nil {
		s.logger.LogAuditError("", "create_user", "failed", "Failed to hash password", err)
		return nil, fmt.Errorf("failed to prepare user: %w", err)
	}

	// Generate TOTP secret using TOTP service
	totpKey, err := s.totpService.GenerateSecret("PasswordManager", req.Username)
	if err != nil {
		s.logger.LogAuditError("", "create_user", "failed", "Failed to generate TOTP secret", err)
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// Create user entity
	userID := uuid.New()
	user := &domain.User{
		ID:           userID,
		Username:     req.Username,
		PasswordHash: hashedPassword,
		TOTPSecret:   totpKey.Secret(),
		Role:         req.Role,
		CreatedAt:    time.Now(),
	}

	// Store user via repository
	if err := s.userRepo.Create(ctx, user); err != nil {
		s.logger.LogAuditError(userID.String(), "create_user", "failed", "Failed to create user", err)
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	s.logger.LogAuditInfo(userID.String(), "create_user", "success", fmt.Sprintf("User created: %s", req.Username))
	logrus.WithFields(logrus.Fields{
		"username": req.Username,
		"user_id":  userID.String(),
		"role":     req.Role,
	}).Info("User created successfully")

	return &CreateUserResult{
		UserID:     userID,
		Username:   req.Username,
		Role:       req.Role,
		TOTPSecret: totpKey.URL(), // QR code URL for user setup
		CreatedAt:  user.CreatedAt,
	}, nil
}

// UpdateUser updates an existing user with the provided information.
// It handles password hashing if a new password is provided and
// coordinates the update through the repository.
//
// Parameters:
//
//	ctx: The context for the operation.
//	req: The user update request with optional fields.
//
// Returns:
//
//	An error if the update fails.
func (s *userService) UpdateUser(ctx context.Context, req UpdateUserRequest) error {
	logrus.WithField("user_id", req.UserID.String()).Info("Updating user")

	// Get existing user
	existingUser, err := s.userRepo.Read(ctx, req.UserID)
	if err != nil {
		s.logger.LogAuditError(req.UserID.String(), "update_user", "failed", "User not found", err)
		return fmt.Errorf("user not found: %w", err)
	}

	// Prepare updated user
	updatedUser := *existingUser

	// Update username if provided
	if req.Username != nil {
		updatedUser.Username = *req.Username
	}

	// Update password if provided
	if req.Password != nil {
		hashedPassword, err := s.passwordService.HashPassword(*req.Password)
		if err != nil {
			s.logger.LogAuditError(req.UserID.String(), "update_user", "failed", "Failed to hash password", err)
			return fmt.Errorf("failed to hash password: %w", err)
		}
		updatedUser.PasswordHash = hashedPassword
	}

	// Update role if provided
	if req.Role != nil {
		updatedUser.Role = *req.Role
	}

	// Update user via repository
	if err := s.userRepo.Update(ctx, &updatedUser); err != nil {
		s.logger.LogAuditError(req.UserID.String(), "update_user", "failed", "Failed to update user", err)
		return fmt.Errorf("failed to update user: %w", err)
	}

	s.logger.LogAuditInfo(req.UserID.String(), "update_user", "success", fmt.Sprintf("User updated: %s", updatedUser.Username))
	logrus.WithFields(logrus.Fields{
		"user_id":  req.UserID.String(),
		"username": updatedUser.Username,
	}).Info("User updated successfully")

	return nil
}

// GetUser retrieves a user by ID.
//
// Parameters:
//
//	ctx: The context for the operation.
//	userID: The user's unique identifier.
//
// Returns:
//
//	The user information or an error if not found.
func (s *userService) GetUser(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	return s.userRepo.Read(ctx, userID)
}

// GetUserByUsername retrieves a user by username.
//
// Parameters:
//
//	ctx: The context for the operation.
//	username: The user's username.
//
// Returns:
//
//	The user information or an error if not found.
func (s *userService) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	user, err := s.userRepo.ReadByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// ListUsers retrieves all users from the system.
//
// Parameters:
//
//	ctx: The context for the operation.
//
// Returns:
//
//	A slice of all users or an error if retrieval fails.
func (s *userService) ListUsers(ctx context.Context) ([]domain.User, error) {
	return s.userRepo.List(ctx)
}

// DeleteUser removes a user from the system.
//
// Parameters:
//
//	ctx: The context for the operation.
//	userID: The user's unique identifier.
//
// Returns:
//
//	An error if deletion fails.
func (s *userService) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	if err := s.userRepo.Delete(ctx, userID); err != nil {
		s.logger.LogAuditError(userID.String(), "delete_user", "failed", "Failed to delete user", err)
		return fmt.Errorf("failed to delete user: %w", err)
	}

	s.logger.LogAuditInfo(userID.String(), "delete_user", "success", "User deleted successfully")
	return nil
}

// ValidateBootstrapToken validates a bootstrap token for initial admin user creation.
//
// Parameters:
//
//	ctx: The context for the operation.
//	token: The bootstrap token to validate.
//
// Returns:
//
//	True if the token is valid, false otherwise, and an error if validation fails.
func (s *userService) ValidateBootstrapToken(ctx context.Context, token string) (bool, error) {
	return s.userRepo.ValidateBootstrapToken(ctx, token)
}

// InvalidateBootstrapToken marks a bootstrap token as used.
//
// Parameters:
//
//	ctx: The context for the operation.
//	token: The bootstrap token to invalidate.
//
// Returns:
//
//	An error if invalidation fails.
func (s *userService) InvalidateBootstrapToken(ctx context.Context, token string) error {
	return s.userRepo.InvalidateBootstrapToken(ctx, token)
}
