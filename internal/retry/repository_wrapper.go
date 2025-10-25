package retry

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Repository defines the basic CRUD operations that can be wrapped with retry logic.
type Repository[T any] interface {
	Create(ctx context.Context, entity T) error
	Read(ctx context.Context, id uuid.UUID) (T, error)
	Update(ctx context.Context, entity T) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// RetryableRepository wraps a repository with retry logic for all operations.
type RetryableRepository[T any] struct {
	repo       Repository[T]
	retryPolicy Policy
}

// NewRetryableRepository creates a new retryable repository wrapper.
func NewRetryableRepository[T any](repo Repository[T], policy Policy) *RetryableRepository[T] {
	return &RetryableRepository[T]{
		repo:       repo,
		retryPolicy: policy,
	}
}

// Create wraps the Create operation with retry logic.
func (r *RetryableRepository[T]) Create(ctx context.Context, entity T) error {
	return WithExponentialBackoff(ctx, r.retryPolicy, func() error {
		return r.repo.Create(ctx, entity)
	})
}

// Read wraps the Read operation with retry logic.
func (r *RetryableRepository[T]) Read(ctx context.Context, id uuid.UUID) (T, error) {
	return WithExponentialBackoffResult(ctx, r.retryPolicy, func() (T, error) {
		return r.repo.Read(ctx, id)
	})
}

// Update wraps the Update operation with retry logic.
func (r *RetryableRepository[T]) Update(ctx context.Context, entity T) error {
	return WithExponentialBackoff(ctx, r.retryPolicy, func() error {
		return r.repo.Update(ctx, entity)
	})
}

// Delete wraps the Delete operation with retry logic.
func (r *RetryableRepository[T]) Delete(ctx context.Context, id uuid.UUID) error {
	return WithExponentialBackoff(ctx, r.retryPolicy, func() error {
		return r.repo.Delete(ctx, id)
	})
}

// TransactionRepository extends Repository with transaction operations.
type TransactionRepository[T any] interface {
	Repository[T]
	BeginTx(ctx context.Context) (Transaction[T], error)
}

// Transaction represents a database transaction.
type Transaction[T any] interface {
	Create(ctx context.Context, entity T) error
	Update(ctx context.Context, entity T) error
	Delete(ctx context.Context, id uuid.UUID) error
	Commit() error
	Rollback() error
}

// RetryableTransactionRepository wraps a transaction repository with retry logic.
type RetryableTransactionRepository[T any] struct {
	repo       TransactionRepository[T]
	retryPolicy Policy
}

// NewRetryableTransactionRepository creates a new retryable transaction repository wrapper.
func NewRetryableTransactionRepository[T any](repo TransactionRepository[T], policy Policy) *RetryableTransactionRepository[T] {
	return &RetryableTransactionRepository[T]{
		repo:       repo,
		retryPolicy: policy,
	}
}

// BeginTx wraps the BeginTx operation with retry logic.
func (r *RetryableTransactionRepository[T]) BeginTx(ctx context.Context) (Transaction[T], error) {
	return WithExponentialBackoffResult(ctx, r.retryPolicy, func() (Transaction[T], error) {
		tx, err := r.repo.BeginTx(ctx)
		if err != nil {
			return nil, err
		}
		return &retryableTransaction[T]{tx: tx, policy: r.retryPolicy}, nil
	})
}

// Create wraps the Create operation with retry logic.
func (r *RetryableTransactionRepository[T]) Create(ctx context.Context, entity T) error {
	return WithExponentialBackoff(ctx, r.retryPolicy, func() error {
		return r.repo.Create(ctx, entity)
	})
}

// Read wraps the Read operation with retry logic.
func (r *RetryableTransactionRepository[T]) Read(ctx context.Context, id uuid.UUID) (T, error) {
	return WithExponentialBackoffResult(ctx, r.retryPolicy, func() (T, error) {
		return r.repo.Read(ctx, id)
	})
}

// Update wraps the Update operation with retry logic.
func (r *RetryableTransactionRepository[T]) Update(ctx context.Context, entity T) error {
	return WithExponentialBackoff(ctx, r.retryPolicy, func() error {
		return r.repo.Update(ctx, entity)
	})
}

// Delete wraps the Delete operation with retry logic.
func (r *RetryableTransactionRepository[T]) Delete(ctx context.Context, id uuid.UUID) error {
	return WithExponentialBackoff(ctx, r.retryPolicy, func() error {
		return r.repo.Delete(ctx, id)
	})
}

// retryableTransaction wraps a transaction with retry logic for commit/rollback.
type retryableTransaction[T any] struct {
	tx     Transaction[T]
	policy Policy
}

func (r *retryableTransaction[T]) Create(ctx context.Context, entity T) error {
	return r.tx.Create(ctx, entity)
}

func (r *retryableTransaction[T]) Update(ctx context.Context, entity T) error {
	return r.tx.Update(ctx, entity)
}

func (r *retryableTransaction[T]) Delete(ctx context.Context, id uuid.UUID) error {
	return r.tx.Delete(ctx, id)
}

func (r *retryableTransaction[T]) Commit() error {
	return WithExponentialBackoff(context.Background(), r.policy, func() error {
		return r.tx.Commit()
	})
}

func (r *retryableTransaction[T]) Rollback() error {
	return WithExponentialBackoff(context.Background(), r.policy, func() error {
		return r.tx.Rollback()
	})
}

// HTTPClient defines the interface for HTTP operations that can be retried.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// RetryableHTTPClient wraps an HTTP client with retry logic.
type RetryableHTTPClient struct {
	client      HTTPClient
	retryPolicy Policy
	cb          *CircuitBreaker
}

// NewRetryableHTTPClient creates a new retryable HTTP client.
func NewRetryableHTTPClient(client HTTPClient, policy Policy, circuitBreaker *CircuitBreaker) *RetryableHTTPClient {
	return &RetryableHTTPClient{
		client:      client,
		retryPolicy: policy,
		cb:          circuitBreaker,
	}
}

// Do executes an HTTP request with retry logic and circuit breaker protection.
func (c *RetryableHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if !c.retryPolicy.Enabled {
		if c.cb != nil {
			var resp *http.Response
			err := c.cb.Execute(func() error {
				var err error
				resp, err = c.client.Do(req)
				return err
			})
			return resp, err
		}
		return c.client.Do(req)
	}

	var lastResp *http.Response
	var lastErr error

	for attempt := 0; attempt < c.retryPolicy.MaxAttempts; attempt++ {
		// Check context cancellation
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		default:
		}

		// Execute with circuit breaker if configured
		var resp *http.Response
		var err error

		if c.cb != nil {
			err = c.cb.Execute(func() error {
				resp, err = c.client.Do(req)
				return err
			})
		} else {
			resp, err = c.client.Do(req)
		}

		lastResp = resp
		lastErr = err

		if err == nil && resp.StatusCode < 500 {
			// Success or client error (don't retry 4xx errors)
			return resp, nil
		}

		// Check if error is retryable
		if err != nil && !IsRetryable(err, c.retryPolicy) {
			return nil, fmt.Errorf("%w: %v", ErrNonRetryable, err)
		}

		// Don't sleep after the last attempt
		if attempt == c.retryPolicy.MaxAttempts-1 {
			break
		}

		// Calculate delay with exponential backoff
		delay := calculateDelay(attempt, c.retryPolicy)

		// Sleep with context cancellation support
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	return lastResp, lastErr
}

// ConnectionWrapper wraps connection operations with retry logic.
type ConnectionWrapper struct {
	retryPolicy Policy
}

// NewConnectionWrapper creates a new connection wrapper.
func NewConnectionWrapper(policy Policy) *ConnectionWrapper {
	return &ConnectionWrapper{
		retryPolicy: policy,
	}
}

// Execute wraps a connection operation with retry logic.
func (w *ConnectionWrapper) Execute(ctx context.Context, operation func() error) error {
	return WithExponentialBackoff(ctx, w.retryPolicy, operation)
}

// ExecuteString wraps a connection operation that returns a string with retry logic.
func (w *ConnectionWrapper) ExecuteString(ctx context.Context, operation func() (string, error)) (string, error) {
	return WithExponentialBackoffResult(ctx, w.retryPolicy, operation)
}

// ExecuteInt wraps a connection operation that returns an int with retry logic.
func (w *ConnectionWrapper) ExecuteInt(ctx context.Context, operation func() (int, error)) (int, error) {
	return WithExponentialBackoffResult(ctx, w.retryPolicy, operation)
}

// ExecuteBool wraps a connection operation that returns a bool with retry logic.
func (w *ConnectionWrapper) ExecuteBool(ctx context.Context, operation func() (bool, error)) (bool, error) {
	return WithExponentialBackoffResult(ctx, w.retryPolicy, operation)
}

// RetryMetrics tracks retry operation metrics.
type RetryMetrics struct {
	TotalAttempts   int64
	SuccessCount    int64
	FailureCount    int64
	RetryCount      int64
	CircuitBreakerOpens int64
}

// MetricsCollector collects retry metrics for monitoring.
type MetricsCollector interface {
	RecordRetryAttempt(operation string, attempt int, success bool)
	RecordCircuitBreakerStateChange(operation string, oldState, newState CircuitState)
}

// LoggingMetricsCollector implements MetricsCollector with logging.
type LoggingMetricsCollector struct {
	logger interface {
		Info(msg string, keysAndValues ...interface{})
		Error(msg string, keysAndValues ...interface{})
	}
}

// NewLoggingMetricsCollector creates a new logging metrics collector.
func NewLoggingMetricsCollector(logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
}) *LoggingMetricsCollector {
	return &LoggingMetricsCollector{logger: logger}
}

// RecordRetryAttempt logs retry attempt information.
func (l *LoggingMetricsCollector) RecordRetryAttempt(operation string, attempt int, success bool) {
	if success {
		l.logger.Info("retry operation succeeded",
			"operation", operation,
			"attempt", attempt+1,
		)
	} else {
		l.logger.Info("retry operation failed",
			"operation", operation,
			"attempt", attempt+1,
		)
	}
}

// RecordCircuitBreakerStateChange logs circuit breaker state changes.
func (l *LoggingMetricsCollector) RecordCircuitBreakerStateChange(operation string, oldState, newState CircuitState) {
	l.logger.Info("circuit breaker state changed",
		"operation", operation,
		"old_state", oldState.String(),
		"new_state", newState.String(),
	)
}

// String returns a string representation of the circuit state.
func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}