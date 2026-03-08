package secrets

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
)

// TagService handles tag management operations for secrets.
// It provides functionality to add, remove, and query tags
// while maintaining separation from secret storage concerns.
type TagService interface {
	AddTags(ctx context.Context, secretID uuid.UUID, tags []string) error
	RemoveTags(ctx context.Context, secretID uuid.UUID, tags []string) error
	RemoveAllTags(ctx context.Context, secretID uuid.UUID) error
	GetTags(ctx context.Context, secretID uuid.UUID) ([]string, error)
	FindSecretsByTags(ctx context.Context, userID uuid.UUID, tags []string) ([]uuid.UUID, error)
}

// tagService implements TagService by delegating to a tag repository.
type tagService struct {
	tagRepo repositories.SecretTagRepositoryInterface
	logger  *logging.Logger
}

// NewTagService creates a new TagService backed by the given repository.
func NewTagService(tagRepo repositories.SecretTagRepositoryInterface, logger *logging.Logger) TagService {
	return &tagService{
		tagRepo: tagRepo,
		logger:  logger,
	}
}

// AddTags adds the specified tags to a secret.
// It inserts new tag associations while avoiding duplicates.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	secretID: The secret's unique identifier.
//	tags: The tags to add to the secret.
//
// Returns:
//
//	An error if the operation fails.
func (s *tagService) AddTags(ctx context.Context, secretID uuid.UUID, tags []string) error {
	if len(tags) == 0 {
		return nil
	}

	if err := s.tagRepo.AddTags(ctx, secretID, tags); err != nil {
		s.logger.LogAuditError(secretID.String(), "add_tags", "failed", "Failed to add tags", err)
		return fmt.Errorf("add tags: %w", err)
	}

	s.logger.LogAuditInfo(secretID.String(), "add_tags", "success",
		fmt.Sprintf("Added %d tags to secret", len(tags)))
	logrus.WithFields(logrus.Fields{
		"secret_id": secretID.String(),
		"tag_count": len(tags),
	}).Debug("Tags added to secret")

	return nil
}

// RemoveTags removes the specified tags from a secret.
// It deletes the tag associations from the database.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	secretID: The secret's unique identifier.
//	tags: The tags to remove from the secret.
//
// Returns:
//
//	An error if the operation fails.
func (s *tagService) RemoveTags(ctx context.Context, secretID uuid.UUID, tags []string) error {
	if len(tags) == 0 {
		return nil
	}

	if err := s.tagRepo.RemoveTags(ctx, secretID, tags); err != nil {
		s.logger.LogAuditError(secretID.String(), "remove_tags", "failed", "Failed to remove tags", err)
		return fmt.Errorf("remove tags: %w", err)
	}

	s.logger.LogAuditInfo(secretID.String(), "remove_tags", "success",
		fmt.Sprintf("Removed %d tags from secret", len(tags)))
	logrus.WithFields(logrus.Fields{
		"secret_id": secretID.String(),
		"tag_count": len(tags),
	}).Debug("Tags removed from secret")

	return nil
}

// RemoveAllTags removes all tags from a secret.
// It deletes all tag associations for the specified secret.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	secretID: The secret's unique identifier.
//
// Returns:
//
//	An error if the operation fails.
func (s *tagService) RemoveAllTags(ctx context.Context, secretID uuid.UUID) error {
	if err := s.tagRepo.RemoveAllTags(ctx, secretID); err != nil {
		s.logger.LogAuditError(secretID.String(), "remove_all_tags", "failed", "Failed to remove all tags", err)
		return fmt.Errorf("remove all tags: %w", err)
	}

	s.logger.LogAuditInfo(secretID.String(), "remove_all_tags", "success", "Removed all tags from secret")
	logrus.WithField("secret_id", secretID.String()).Debug("All tags removed from secret")

	return nil
}

// GetTags retrieves all tags associated with a secret.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	secretID: The secret's unique identifier.
//
// Returns:
//
//	A slice of tags associated with the secret, or an error if the operation fails.
func (s *tagService) GetTags(ctx context.Context, secretID uuid.UUID) ([]string, error) {
	tags, err := s.tagRepo.GetTags(ctx, secretID)
	if err != nil {
		s.logger.LogAuditError(secretID.String(), "get_tags", "failed", "Failed to get tags", err)
		return nil, fmt.Errorf("get tags: %w", err)
	}
	return tags, nil
}

// FindSecretsByTags finds all secrets for a user that have any of the specified tags.
// It performs a query to find secrets matching the tag criteria.
//
// Parameters:
//
//	ctx: The context for the database operation.
//	userID: The user's unique identifier.
//	tags: The tags to search for.
//
// Returns:
//
//	A slice of secret IDs that have any of the specified tags, or an error if the operation fails.
func (s *tagService) FindSecretsByTags(ctx context.Context, userID uuid.UUID, tags []string) ([]uuid.UUID, error) {
	if len(tags) == 0 {
		return []uuid.UUID{}, nil
	}

	secretIDs, err := s.tagRepo.FindSecretsByTags(ctx, userID, tags)
	if err != nil {
		s.logger.LogAuditError(userID.String(), "find_secrets_by_tags", "failed", "Failed to find secrets by tags", err)
		return nil, fmt.Errorf("find secrets by tags: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"user_id":       userID.String(),
		"tags":          tags,
		"secrets_found": len(secretIDs),
	}).Debug("Found secrets by tags")

	return secretIDs, nil
}
