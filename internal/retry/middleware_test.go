package retry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPMiddleware_Success(t *testing.T) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      10 * time.Millisecond,
		MaxDelay:          100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
	}

	var attempts int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	middleware := NewHTTPMiddleware(policy, nil)
	server := httptest.NewServer(middleware.Middleware(handler))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	if atomic.LoadInt32(&attempts) != 1 {
		t.Errorf("expected 1 attempt, got %d", attempts)
	}
}

func TestHTTPMiddleware_RetryOnServerError(t *testing.T) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      10 * time.Millisecond,
		MaxDelay:          100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
		RetryableStatuses: []int{500, 502, 503, 504}, // Retry on server errors
	}

	var attempts int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&attempts, 1)
		if current == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("server error"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	middleware := NewHTTPMiddleware(policy, nil)
	server := httptest.NewServer(middleware.Middleware(handler))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	if atomic.LoadInt32(&attempts) != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

func TestHTTPMiddleware_NoRetryOnClientError(t *testing.T) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      10 * time.Millisecond,
		MaxDelay:          100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
	}

	var attempts int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	})

	middleware := NewHTTPMiddleware(policy, nil)
	server := httptest.NewServer(middleware.Middleware(handler))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}

	if atomic.LoadInt32(&attempts) != 1 {
		t.Errorf("expected 1 attempt (no retry), got %d", attempts)
	}
}

func TestHTTPMiddleware_MaxAttemptsExceeded(t *testing.T) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      10 * time.Millisecond,
		MaxDelay:          100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
		RetryableStatuses: []int{500, 502, 503, 504}, // Retry on server errors
	}

	var attempts int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	})

	middleware := NewHTTPMiddleware(policy, nil)
	server := httptest.NewServer(middleware.Middleware(handler))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", resp.StatusCode)
	}

	if atomic.LoadInt32(&attempts) != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestHTTPMiddleware_ContextCancellation(t *testing.T) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       5,
		InitialDelay:      50 * time.Millisecond,
		MaxDelay:          200 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
		RetryableStatuses: []int{500, 502, 503, 504}, // Retry on server errors
	}

	var attempts int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	})

	middleware := NewHTTPMiddleware(policy, nil)
	server := httptest.NewServer(middleware.Middleware(handler))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	req, err := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Error("expected error due to context cancellation")
	}

	if atomic.LoadInt32(&attempts) > 2 {
		t.Errorf("expected at most 2 attempts before cancellation, got %d", attempts)
	}
}

func TestHTTPMiddleware_Disabled(t *testing.T) {
	policy := Policy{
		Enabled:           false,
		MaxAttempts:       3,
		InitialDelay:      10 * time.Millisecond,
		MaxDelay:          100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
	}

	var attempts int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	})

	middleware := NewHTTPMiddleware(policy, nil)
	server := httptest.NewServer(middleware.Middleware(handler))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}

	if atomic.LoadInt32(&attempts) != 1 {
		t.Errorf("expected 1 attempt (no retry), got %d", attempts)
	}
}

func TestClientMiddleware_Success(t *testing.T) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      10 * time.Millisecond,
		MaxDelay:          100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
	}

	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	middleware := NewClientMiddleware(policy, nil)
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}

	resp, err := middleware.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	if atomic.LoadInt32(&attempts) != 1 {
		t.Errorf("expected 1 attempt, got %d", attempts)
	}
}

func TestClientMiddleware_RetryOnServerError(t *testing.T) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      10 * time.Millisecond,
		MaxDelay:          100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
		RetryableStatuses: []int{500, 502, 503, 504}, // Retry on server errors
	}

	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&attempts, 1)
		if current == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("server error"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	middleware := NewClientMiddleware(policy, nil)
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}

	resp, err := middleware.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	if atomic.LoadInt32(&attempts) != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

func TestClientMiddleware_RetryOnNetworkError(t *testing.T) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      10 * time.Millisecond,
		MaxDelay:          100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		RetryableErrors:   []string{"connection refused", "EOF"},
		JitterEnabled:     false,
	}

	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&attempts, 1)
		if current == 1 {
			// Close the connection to simulate network error
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
			}
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	middleware := NewClientMiddleware(policy, nil)
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}

	resp, err := middleware.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	if atomic.LoadInt32(&attempts) != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

func TestRetryableTransport(t *testing.T) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      10 * time.Millisecond,
		MaxDelay:          100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
		RetryableStatuses: []int{500, 502, 503, 504}, // Retry on server errors
	}

	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&attempts, 1)
		if current == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("server error"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	transport := NewRetryableTransport(nil, policy, nil)
	client := &http.Client{Transport: transport}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	if atomic.LoadInt32(&attempts) != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

func TestHTTPMiddlewareWithOptions(t *testing.T) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       2,
		InitialDelay:      10 * time.Millisecond,
		MaxDelay:          100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
	}

	var metricsCalled bool
	metrics := &mockMetricsCollector{
		recordRetryAttemptFunc: func(operation string, attempt int, success bool) {
			metricsCalled = true
		},
	}

	middleware := NewHTTPMiddlewareWithOptions(
		WithRetryPolicy(policy),
		WithMetricsCollector(metrics),
	)

	var attempts int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(middleware.Middleware(handler))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if !metricsCalled {
		t.Error("expected metrics collector to be called")
	}
}

func TestClientMiddlewareWithOptions(t *testing.T) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       2,
		InitialDelay:      10 * time.Millisecond,
		MaxDelay:          100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
	}

	var metricsCalled bool
	metrics := &mockMetricsCollector{
		recordRetryAttemptFunc: func(operation string, attempt int, success bool) {
			metricsCalled = true
		},
	}

	middleware := NewClientMiddlewareWithOptions(
		WithClientRetryPolicy(policy),
		WithClientMetricsCollector(metrics),
	)

	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error creating request: %v", err)
	}

	resp, err := middleware.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if !metricsCalled {
		t.Error("expected metrics collector to be called")
	}
}

func TestDefaultHTTPRetryConfig(t *testing.T) {
	config := DefaultHTTPRetryConfig()

	if config.MaxAttempts != 3 {
		t.Errorf("expected max attempts 3, got %d", config.MaxAttempts)
	}

	if config.InitialDelay != 100*time.Millisecond {
		t.Errorf("expected initial delay 100ms, got %v", config.InitialDelay)
	}

	if config.MaxDelay != 5*time.Second {
		t.Errorf("expected max delay 5s, got %v", config.MaxDelay)
	}

	if len(config.RetryableStatuses) != 5 {
		t.Errorf("expected 5 retryable statuses, got %d", len(config.RetryableStatuses))
	}
}

// mockMetricsCollector is a mock implementation of MetricsCollector for testing.
type mockMetricsCollector struct {
	recordRetryAttemptFunc              func(operation string, attempt int, success bool)
	recordCircuitBreakerStateChangeFunc func(operation string, oldState, newState CircuitState)
}

func (m *mockMetricsCollector) RecordRetryAttempt(operation string, attempt int, success bool) {
	if m.recordRetryAttemptFunc != nil {
		m.recordRetryAttemptFunc(operation, attempt, success)
	}
}

func (m *mockMetricsCollector) RecordCircuitBreakerStateChange(operation string, oldState, newState CircuitState) {
	if m.recordCircuitBreakerStateChangeFunc != nil {
		m.recordCircuitBreakerStateChangeFunc(operation, oldState, newState)
	}
}

// Benchmark tests
func BenchmarkHTTPMiddleware(b *testing.B) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      1 * time.Millisecond,
		MaxDelay:          10 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
	}

	middleware := NewHTTPMiddleware(policy, nil)
	handler := middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := http.Get(server.URL)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
		resp.Body.Close()
	}
}

func BenchmarkClientMiddleware(b *testing.B) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      1 * time.Millisecond,
		MaxDelay:          10 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	middleware := NewClientMiddleware(policy, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, err := http.NewRequest("GET", server.URL, nil)
		if err != nil {
			b.Fatalf("unexpected error creating request: %v", err)
		}
		resp, err := middleware.Do(req)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
		resp.Body.Close()
	}
}
