package retry

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestWithExponentialBackoff_Success(t *testing.T) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      10 * time.Millisecond,
		MaxDelay:          100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
		RetryableErrors:   []string{"temporary error"},
	}

	attempts := 0
	err := WithExponentialBackoff(context.Background(), policy, func() error {
		attempts++
		if attempts == 1 {
			return errors.New("temporary error")
		}
		return nil
	})
	if err != nil {
		t.Errorf("expected success, got error: %v", err)
	}

	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

func TestWithExponentialBackoff_MaxAttemptsExceeded(t *testing.T) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      10 * time.Millisecond,
		MaxDelay:          100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
		RetryableErrors:   []string{"persistent error"},
	}

	attempts := 0
	err := WithExponentialBackoff(context.Background(), policy, func() error {
		attempts++
		return errors.New("persistent error")
	})

	if err == nil {
		t.Error("expected error, got success")
	}

	if !errors.Is(err, ErrMaxRetriesExceeded) {
		t.Errorf("expected ErrMaxRetriesExceeded, got: %v", err)
	}

	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestWithExponentialBackoff_Disabled(t *testing.T) {
	policy := Policy{
		Enabled:           false,
		MaxAttempts:       3,
		InitialDelay:      10 * time.Millisecond,
		MaxDelay:          100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
	}

	attempts := 0
	err := WithExponentialBackoff(context.Background(), policy, func() error {
		attempts++
		return errors.New("error")
	})

	if err == nil {
		t.Error("expected error, got success")
	}

	if attempts != 1 {
		t.Errorf("expected 1 attempt (no retry), got %d", attempts)
	}
}

func TestWithExponentialBackoff_ContextCancellation(t *testing.T) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       5,
		InitialDelay:      100 * time.Millisecond,
		MaxDelay:          1 * time.Second,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
		RetryableErrors:   []string{"error"},
	}

	ctx, cancel := context.WithCancel(context.Background())

	attempts := 0
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := WithExponentialBackoff(ctx, policy, func() error {
		attempts++
		return errors.New("error")
	})

	if err == nil {
		t.Error("expected error, got success")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}

	if attempts > 2 {
		t.Errorf("expected at most 2 attempts before cancellation, got %d", attempts)
	}
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		policy   Policy
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			policy:   DefaultPolicy(),
			expected: false,
		},
		{
			name:     "retryable error interface",
			err:      Retryable(errors.New("retryable")),
			policy:   DefaultPolicy(),
			expected: true,
		},
		{
			name:     "non-retryable error interface",
			err:      NonRetryable(errors.New("not retryable")),
			policy:   DefaultPolicy(),
			expected: false,
		},
		{
			name:     "matching error pattern",
			err:      errors.New("connection refused"),
			policy:   DatabasePolicy(),
			expected: true,
		},
		{
			name:     "non-matching error pattern",
			err:      errors.New("invalid syntax"),
			policy:   DatabasePolicy(),
			expected: false,
		},
		{
			name:     "case insensitive matching",
			err:      errors.New("DATABASE IS LOCKED"),
			policy:   DatabasePolicy(),
			expected: true,
		},
		{
			// go-oidc's actual error text for an HTTP 500 from the issuer,
			// e.g. `oidc: get keys failed: 500 Internal Server Error <body>`.
			// A real upstream 5xx is the most common transient OIDC failure,
			// so external_services must classify this as retryable.
			name:     "external service 500 reason phrase",
			err:      errors.New("oidc: get keys failed: 500 Internal Server Error"),
			policy:   ExternalServicePolicy(),
			expected: true,
		},
		{
			name:     "external service 502 reason phrase",
			err:      errors.New("oidc: token exchange failed: 502 Bad Gateway"),
			policy:   ExternalServicePolicy(),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryable(tt.err, tt.policy)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestCalculateDelay(t *testing.T) {
	tests := []struct {
		name     string
		attempt  int
		policy   Policy
		minDelay time.Duration
		maxDelay time.Duration
	}{
		{
			name:    "first attempt",
			attempt: 0,
			policy: Policy{
				InitialDelay:      100 * time.Millisecond,
				BackoffMultiplier: 2.0,
				MaxDelay:          1 * time.Second,
				JitterEnabled:     false,
			},
			minDelay: 100 * time.Millisecond,
			maxDelay: 100 * time.Millisecond,
		},
		{
			name:    "second attempt",
			attempt: 1,
			policy: Policy{
				InitialDelay:      100 * time.Millisecond,
				BackoffMultiplier: 2.0,
				MaxDelay:          1 * time.Second,
				JitterEnabled:     false,
			},
			minDelay: 200 * time.Millisecond,
			maxDelay: 200 * time.Millisecond,
		},
		{
			name:    "max delay cap",
			attempt: 10,
			policy: Policy{
				InitialDelay:      100 * time.Millisecond,
				BackoffMultiplier: 2.0,
				MaxDelay:          500 * time.Millisecond,
				JitterEnabled:     false,
			},
			minDelay: 500 * time.Millisecond,
			maxDelay: 500 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delay := calculateDelay(tt.attempt, tt.policy)
			if delay < tt.minDelay || delay > tt.maxDelay {
				t.Errorf("expected delay between %v and %v, got %v", tt.minDelay, tt.maxDelay, delay)
			}
		})
	}
}

func TestCircuitBreaker(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 3,
		Timeout:          100 * time.Millisecond,
		HalfOpenRequests: 2,
	}

	cb := NewCircuitBreaker(config)

	// Test initial state
	if cb.GetState() != StateClosed {
		t.Errorf("expected initial state to be closed, got %v", cb.GetState())
	}

	// Test failure threshold
	for i := 0; i < config.FailureThreshold; i++ {
		err := cb.Execute(func() error {
			return errors.New("failure")
		})
		if err == nil {
			t.Error("expected error, got success")
		}
	}

	// Circuit should be open now
	if cb.GetState() != StateOpen {
		t.Errorf("expected state to be open after %d failures, got %v", config.FailureThreshold, cb.GetState())
	}

	// Should return circuit breaker error
	err := cb.Execute(func() error {
		return nil
	})
	if !errors.Is(err, ErrCircuitBreakerOpen) {
		t.Errorf("expected ErrCircuitBreakerOpen, got: %v", err)
	}

	// Wait for timeout
	time.Sleep(config.Timeout + 10*time.Millisecond)

	// Should transition to half-open and allow execution
	executed := false
	err = cb.Execute(func() error {
		executed = true
		return nil
	})
	if err != nil {
		t.Errorf("expected success in half-open state, got: %v", err)
	}
	if !executed {
		t.Error("function should have been executed in half-open state")
	}
}

func TestWithExponentialBackoffResult(t *testing.T) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      10 * time.Millisecond,
		MaxDelay:          100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
		RetryableErrors:   []string{"temporary error"},
	}

	attempts := 0
	result, err := WithExponentialBackoffResult(context.Background(), policy, func() (string, error) {
		attempts++
		if attempts == 1 {
			return "", errors.New("temporary error")
		}
		return "success", nil
	})
	if err != nil {
		t.Errorf("expected success, got error: %v", err)
	}

	if result != "success" {
		t.Errorf("expected 'success', got '%s'", result)
	}

	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

func TestRetryableError(t *testing.T) {
	originalErr := errors.New("test error")

	retryableErr := Retryable(originalErr)
	if !retryableErr.(RetryableError).Retryable() {
		t.Error("expected retryable error to be retryable")
	}

	nonRetryableErr := NonRetryable(originalErr)
	if nonRetryableErr.(RetryableError).Retryable() {
		t.Error("expected non-retryable error to not be retryable")
	}
}

func TestPolicyDefaults(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		check  func(Policy) bool
	}{
		{
			name:   "default policy",
			policy: DefaultPolicy(),
			check: func(p Policy) bool {
				return p.MaxAttempts == 3 && p.InitialDelay == 100*time.Millisecond
			},
		},
		{
			name:   "database policy",
			policy: DatabasePolicy(),
			check: func(p Policy) bool {
				return len(p.RetryableErrors) > 0 && strings.Contains(p.RetryableErrors[0], "connection refused")
			},
		},
		{
			name:   "external service policy",
			policy: ExternalServicePolicy(),
			check: func(p Policy) bool {
				return p.MaxAttempts == 5 && p.InitialDelay == 1*time.Second
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.check(tt.policy) {
				t.Errorf("policy defaults not as expected: %+v", tt.policy)
			}
		})
	}
}

func TestCircuitBreakerConfig(t *testing.T) {
	config := DefaultCircuitBreaker()

	if config.FailureThreshold != 5 {
		t.Errorf("expected failure threshold 5, got %d", config.FailureThreshold)
	}

	if config.Timeout != 60*time.Second {
		t.Errorf("expected timeout 60s, got %v", config.Timeout)
	}

	if config.HalfOpenRequests != 3 {
		t.Errorf("expected half-open requests 3, got %d", config.HalfOpenRequests)
	}
}

// Benchmark tests
func BenchmarkWithExponentialBackoff(b *testing.B) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      1 * time.Millisecond,
		MaxDelay:          10 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = WithExponentialBackoff(context.Background(), policy, func() error {
			return nil
		})
	}
}

func BenchmarkIsRetryable(b *testing.B) {
	policy := DatabasePolicy()
	testErr := errors.New("connection refused")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsRetryable(testErr, policy)
	}
}

func BenchmarkCalculateDelay(b *testing.B) {
	policy := DefaultPolicy()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = calculateDelay(2, policy)
	}
}
