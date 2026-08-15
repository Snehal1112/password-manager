package retry

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
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

func TestCircuitBreaker_HalfOpenAdmissionIsCapped(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 1,
		Timeout:          20 * time.Millisecond,
		HalfOpenRequests: 2,
	}
	cb := NewCircuitBreaker(config)

	// Trip the breaker open.
	_ = cb.Execute(func() error { return errors.New("failure") })
	if cb.GetState() != StateOpen {
		t.Fatalf("expected state to be open after 1 failure, got %v", cb.GetState())
	}

	// Wait for the timeout to elapse, then release far more pre-spawned
	// concurrent callers than HalfOpenRequests allows, all at once via the
	// start channel, right as the breaker becomes eligible to transition.
	time.Sleep(config.Timeout + 10*time.Millisecond)

	const concurrentCallers = 20
	var admittedCount int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(concurrentCallers)
	for i := 0; i < concurrentCallers; i++ {
		go func() {
			defer wg.Done()
			<-start
			_ = cb.Execute(func() error {
				atomic.AddInt32(&admittedCount, 1)
				// Hold "in flight" briefly so concurrent admission attempts
				// genuinely overlap instead of serializing through fast
				// sequential calls.
				time.Sleep(5 * time.Millisecond)
				return nil
			})
		}()
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt32(&admittedCount); got > int32(config.HalfOpenRequests) {
		t.Errorf("expected at most %d calls admitted into the half-open trial, got %d",
			config.HalfOpenRequests, got)
	}
}

func TestCircuitBreaker_HalfOpenFailureReopensImmediately(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 5,
		Timeout:          20 * time.Millisecond,
		HalfOpenRequests: 3,
	}
	cb := NewCircuitBreaker(config)

	for i := 0; i < config.FailureThreshold; i++ {
		_ = cb.Execute(func() error { return errors.New("failure") })
	}
	if cb.GetState() != StateOpen {
		t.Fatalf("expected state to be open after %d failures, got %v", config.FailureThreshold, cb.GetState())
	}

	time.Sleep(config.Timeout + 10*time.Millisecond)

	// Exhaust every half-open trial with failures. This exercises the
	// half-open reopen path directly under a production-shaped config
	// (HalfOpenRequests < FailureThreshold) and asserts the breaker ends up
	// Open again and is still usable after another Timeout — i.e. it never
	// gets stuck denying every future call.
	for i := 0; i < config.HalfOpenRequests; i++ {
		err := cb.Execute(func() error { return errors.New("still failing") })
		if err == nil {
			t.Fatalf("expected trial %d to fail", i)
		}
	}

	if cb.GetState() != StateOpen {
		t.Fatalf("expected state to be open again after every half-open trial failed, got %v", cb.GetState())
	}

	// The breaker must be usable again after another Timeout — proving it
	// didn't wedge.
	time.Sleep(config.Timeout + 10*time.Millisecond)
	executed := false
	err := cb.Execute(func() error {
		executed = true
		return nil
	})
	if err != nil {
		t.Errorf("expected success after breaker reopened and timeout elapsed again, got: %v", err)
	}
	if !executed {
		t.Error("function should have been executed — breaker must not be permanently wedged")
	}
}

func TestCircuitBreaker_LateSuccessDoesNotCausePermanentHalfOpenWedge(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 5,
		Timeout:          20 * time.Millisecond,
		HalfOpenRequests: 3,
	}
	cb := NewCircuitBreaker(config)

	for i := 0; i < config.FailureThreshold; i++ {
		_ = cb.Execute(func() error { return errors.New("failure") })
	}
	if cb.GetState() != StateOpen {
		t.Fatalf("expected open after %d failures, got %v", config.FailureThreshold, cb.GetState())
	}

	// Simulate a closed-state call that was admitted before the trip and
	// completes successfully after it. recordSuccess resets failures to 0
	// unconditionally, regardless of current state — reachable in production
	// whenever multiple concurrent closed-state calls are in flight and one
	// straggles past the call that tripped the breaker.
	cb.recordSuccess()

	time.Sleep(config.Timeout + 10*time.Millisecond)

	// Exhaust every half-open trial with failures. With failures reset to 0
	// by the late success above, a threshold-gated reopen (failures >=
	// FailureThreshold) would never re-trip after only HalfOpenRequests (3)
	// more failures — this is exactly the wedge scenario the fix closes.
	for i := 0; i < config.HalfOpenRequests; i++ {
		err := cb.Execute(func() error { return errors.New("still failing") })
		if err == nil {
			t.Fatalf("expected trial %d to fail", i)
		}
	}

	if cb.GetState() != StateOpen {
		t.Fatalf("expected state open again after every half-open trial failed, got %v — breaker is wedged", cb.GetState())
	}

	time.Sleep(config.Timeout + 10*time.Millisecond)
	executed := false
	err := cb.Execute(func() error {
		executed = true
		return nil
	})
	if err != nil {
		t.Errorf("expected success after breaker reopened and timeout elapsed again, got: %v", err)
	}
	if !executed {
		t.Error("breaker is permanently wedged — function was never executed")
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
