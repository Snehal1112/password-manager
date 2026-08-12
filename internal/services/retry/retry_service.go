package retry

import (
	"context"
	"fmt"

	"github.com/spf13/viper"

	"rocketvault/internal/retry"
)

// RetryService provides retry functionality for application operations.
// It manages retry policies and provides retry wrappers for different
// types of operations (database, external services, service operations).
type RetryService interface {
	// ExecuteDatabaseOperation executes a database operation with retry logic
	ExecuteDatabaseOperation(ctx context.Context, operation func() error) error

	// ExecuteExternalServiceOperation executes an external service call with retry logic
	ExecuteExternalServiceOperation(ctx context.Context, operation func() error) error

	// ExecuteServiceOperation executes an internal service operation with retry logic
	ExecuteServiceOperation(ctx context.Context, operation func() error) error

	// GetDatabasePolicy returns the database retry policy
	GetDatabasePolicy() retry.Policy

	// GetExternalServicesPolicy returns the external services retry policy
	GetExternalServicesPolicy() retry.Policy

	// GetServiceOperationsPolicy returns the service operations retry policy
	GetServiceOperationsPolicy() retry.Policy
}

// retryService implements RetryService with configurable policies
type retryService struct {
	databasePolicy          retry.Policy
	externalServicesPolicy  retry.Policy
	serviceOperationsPolicy retry.Policy
}

// NewRetryService creates a new retry service with policies loaded from configuration
func NewRetryService(viper *viper.Viper) (RetryService, error) {
	// Load retry configuration
	config, err := retry.LoadConfigFromViper(viper)
	if err != nil {
		return nil, fmt.Errorf("failed to load retry configuration: %w", err)
	}

	return &retryService{
		databasePolicy:          config.Database,
		externalServicesPolicy:  config.ExternalServices,
		serviceOperationsPolicy: config.ServiceOperations,
	}, nil
}

// ExecuteDatabaseOperation executes a database operation with retry logic
func (s *retryService) ExecuteDatabaseOperation(ctx context.Context, operation func() error) error {
	return retry.WithExponentialBackoff(ctx, s.databasePolicy, operation)
}

// ExecuteExternalServiceOperation executes an external service call with retry logic
func (s *retryService) ExecuteExternalServiceOperation(ctx context.Context, operation func() error) error {
	return retry.WithExponentialBackoff(ctx, s.externalServicesPolicy, operation)
}

// ExecuteServiceOperation executes an internal service operation with retry logic
func (s *retryService) ExecuteServiceOperation(ctx context.Context, operation func() error) error {
	return retry.WithExponentialBackoff(ctx, s.serviceOperationsPolicy, operation)
}

// GetDatabasePolicy returns the database retry policy
func (s *retryService) GetDatabasePolicy() retry.Policy {
	return s.databasePolicy
}

// GetExternalServicesPolicy returns the external services retry policy
func (s *retryService) GetExternalServicesPolicy() retry.Policy {
	return s.externalServicesPolicy
}

// GetServiceOperationsPolicy returns the service operations retry policy
func (s *retryService) GetServiceOperationsPolicy() retry.Policy {
	return s.serviceOperationsPolicy
}
