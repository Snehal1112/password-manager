package retry

import (
	"fmt"
	"net/http"
	"time"
)

// HTTPMiddleware provides retry functionality for HTTP handlers.
type HTTPMiddleware struct {
	retryPolicy Policy
	metrics     MetricsCollector
}

// NewHTTPMiddleware creates a new HTTP retry middleware.
func NewHTTPMiddleware(policy Policy, metrics MetricsCollector) *HTTPMiddleware {
	return &HTTPMiddleware{
		retryPolicy: policy,
		metrics:     metrics,
	}
}

// Middleware returns an HTTP middleware function that retries failed requests.
func (m *HTTPMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.retryPolicy.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Create a response writer that captures the status code
		recorder := &responseRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
			header:         make(http.Header),
		}

		var lastErr error
		operationName := fmt.Sprintf("%s %s", r.Method, r.URL.Path)

		for attempt := 0; attempt < m.retryPolicy.MaxAttempts; attempt++ {
			// Check context cancellation
			select {
			case <-r.Context().Done():
				if lastErr != nil {
					http.Error(w, lastErr.Error(), http.StatusInternalServerError)
				} else {
					http.Error(w, "request cancelled", http.StatusRequestTimeout)
				}
				return
			default:
			}

			// Reset the response recorder for each attempt
			recorder.statusCode = http.StatusOK
			recorder.body = nil
			recorder.written = false
			recorder.header = make(http.Header)

			// Create a new request for each attempt (body can only be read once)
			req := r.Clone(r.Context())

			// Execute the handler
			next.ServeHTTP(recorder, req)

			// Check if the request was successful
			if recorder.statusCode < 500 {
				// Success or client error - don't retry
				if m.metrics != nil {
					m.metrics.RecordRetryAttempt(operationName, attempt, true)
				}

				// Write the successful response
				for key, values := range recorder.header {
					for _, value := range values {
						w.Header().Add(key, value)
					}
				}
				w.WriteHeader(recorder.statusCode)
				if len(recorder.body) > 0 {
					w.Write(recorder.body) //nolint:errcheck
				}
				return
			}

			// Server error - check if it's retryable
			if !IsRetryableStatus(recorder.statusCode, m.retryPolicy) {
				if m.metrics != nil {
					m.metrics.RecordRetryAttempt(operationName, attempt, false)
				}

				// Write the non-retryable error response
				for key, values := range recorder.header {
					for _, value := range values {
						w.Header().Add(key, value)
					}
				}
				w.WriteHeader(recorder.statusCode)
				if len(recorder.body) > 0 {
					w.Write(recorder.body) //nolint:errcheck
				}
				return
			}

			lastErr = fmt.Errorf("HTTP %d: server error", recorder.statusCode)

			if m.metrics != nil {
				m.metrics.RecordRetryAttempt(operationName, attempt, false)
			}

			// Don't sleep after the last attempt
			if attempt == m.retryPolicy.MaxAttempts-1 {
				break
			}

			// Calculate delay with exponential backoff
			delay := calculateDelay(attempt, m.retryPolicy)

			// Sleep with context cancellation support
			select {
			case <-r.Context().Done():
				http.Error(w, "request cancelled during retry", http.StatusRequestTimeout)
				return
			case <-time.After(delay):
				// Continue to next attempt
			}
		}

		// All attempts failed - return a 502 Bad Gateway error
		if lastErr != nil {
			http.Error(w, fmt.Sprintf("max retries exceeded: %v", lastErr), http.StatusBadGateway)
		} else {
			http.Error(w, "max retries exceeded", http.StatusBadGateway)
		}
	})
}

// responseRecorder captures HTTP response details for retry logic.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       []byte
	header     http.Header
	written    bool
}

func (r *responseRecorder) WriteHeader(code int) {
	if !r.written {
		r.statusCode = code
		r.written = true
	}
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	if !r.written {
		r.WriteHeader(http.StatusOK)
	}
	r.body = append(r.body, data...)
	return len(data), nil
}

func (r *responseRecorder) Header() http.Header {
	if r.header == nil {
		r.header = make(http.Header)
	}
	return r.header
}

// ClientMiddleware provides retry functionality for HTTP clients.
type ClientMiddleware struct {
	retryPolicy Policy
	metrics     MetricsCollector
}

// NewClientMiddleware creates a new HTTP client retry middleware.
func NewClientMiddleware(policy Policy, metrics MetricsCollector) *ClientMiddleware {
	return &ClientMiddleware{
		retryPolicy: policy,
		metrics:     metrics,
	}
}

// Do executes an HTTP request with retry logic.
func (m *ClientMiddleware) Do(req *http.Request) (*http.Response, error) {
	if !m.retryPolicy.Enabled {
		return http.DefaultClient.Do(req)
	}

	var lastResp *http.Response
	var lastErr error
	operationName := fmt.Sprintf("%s %s", req.Method, req.URL.String())

	for attempt := 0; attempt < m.retryPolicy.MaxAttempts; attempt++ {
		// Check context cancellation
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		default:
		}

		// Create a new request for each attempt
		attemptReq := req.Clone(req.Context())

		// Execute the request
		resp, err := http.DefaultClient.Do(attemptReq)
		lastResp = resp
		lastErr = err

		if err != nil {
			// Network error - check if it's retryable
			if !IsRetryable(err, m.retryPolicy) {
				if m.metrics != nil {
					m.metrics.RecordRetryAttempt(operationName, attempt, false)
				}
				return nil, fmt.Errorf("%w: %v", ErrNonRetryable, err)
			}

			if m.metrics != nil {
				m.metrics.RecordRetryAttempt(operationName, attempt, false)
			}

			// Don't sleep after the last attempt
			if attempt == m.retryPolicy.MaxAttempts-1 {
				break
			}

			// Calculate delay with exponential backoff
			delay := calculateDelay(attempt, m.retryPolicy)

			// Sleep with context cancellation support
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(delay):
				// Continue to next attempt
			}
			continue
		}

		// Check response status code
		if !IsRetryableStatus(resp.StatusCode, m.retryPolicy) {
			// Success, client error, or non-retryable server error - don't retry
			if m.metrics != nil {
				m.metrics.RecordRetryAttempt(operationName, attempt, true)
			}
			return resp, nil
		}

		if m.metrics != nil {
			m.metrics.RecordRetryAttempt(operationName, attempt, false)
		}

		// Don't sleep after the last attempt
		if attempt == m.retryPolicy.MaxAttempts-1 {
			break
		}

		// Calculate delay with exponential backoff
		delay := calculateDelay(attempt, m.retryPolicy)

		// Sleep with context cancellation support
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	// All attempts failed
	if lastErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrMaxRetriesExceeded, lastErr)
	}
	return lastResp, nil
}

// RetryableTransport wraps an http.RoundTripper with retry logic.
type RetryableTransport struct {
	base        http.RoundTripper
	retryPolicy Policy
	metrics     MetricsCollector
}

// NewRetryableTransport creates a new retryable HTTP transport.
func NewRetryableTransport(base http.RoundTripper, policy Policy, metrics MetricsCollector) *RetryableTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &RetryableTransport{
		base:        base,
		retryPolicy: policy,
		metrics:     metrics,
	}
}

// RoundTrip executes an HTTP request with retry logic.
func (t *RetryableTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.retryPolicy.Enabled {
		return t.base.RoundTrip(req)
	}

	middleware := NewClientMiddleware(t.retryPolicy, t.metrics)
	return middleware.Do(req)
}

// RetryConfig provides configuration for HTTP retry middleware.
type RetryConfig struct {
	MaxAttempts       int
	InitialDelay      time.Duration
	MaxDelay          time.Duration
	BackoffMultiplier float64
	RetryableStatuses []int
	JitterEnabled     bool
}

// DefaultHTTPRetryConfig returns a default configuration for HTTP retry middleware.
func DefaultHTTPRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:       3,
		InitialDelay:      100 * time.Millisecond,
		MaxDelay:          5 * time.Second,
		BackoffMultiplier: 2.0,
		RetryableStatuses: []int{500, 502, 503, 504, 429}, // 5xx errors and rate limiting
		JitterEnabled:     true,
	}
}

// HTTPRetryOptions provides functional options for configuring HTTP retry middleware.
type HTTPRetryOptions func(*HTTPMiddleware)

// WithMetricsCollector sets the metrics collector for the retry middleware.
func WithMetricsCollector(metrics MetricsCollector) HTTPRetryOptions {
	return func(m *HTTPMiddleware) {
		m.metrics = metrics
	}
}

// WithRetryPolicy sets a custom retry policy for the middleware.
func WithRetryPolicy(policy Policy) HTTPRetryOptions {
	return func(m *HTTPMiddleware) {
		m.retryPolicy = policy
	}
}

// NewHTTPMiddlewareWithOptions creates a new HTTP retry middleware with options.
func NewHTTPMiddlewareWithOptions(options ...HTTPRetryOptions) *HTTPMiddleware {
	middleware := &HTTPMiddleware{
		retryPolicy: DefaultPolicy(),
	}

	for _, option := range options {
		option(middleware)
	}

	return middleware
}

// HTTPClientOptions provides functional options for configuring HTTP client retry middleware.
type HTTPClientOptions func(*ClientMiddleware)

// WithClientMetricsCollector sets the metrics collector for the client retry middleware.
func WithClientMetricsCollector(metrics MetricsCollector) HTTPClientOptions {
	return func(m *ClientMiddleware) {
		m.metrics = metrics
	}
}

// WithClientRetryPolicy sets a custom retry policy for the client middleware.
func WithClientRetryPolicy(policy Policy) HTTPClientOptions {
	return func(m *ClientMiddleware) {
		m.retryPolicy = policy
	}
}

// NewClientMiddlewareWithOptions creates a new HTTP client retry middleware with options.
func NewClientMiddlewareWithOptions(options ...HTTPClientOptions) *ClientMiddleware {
	middleware := &ClientMiddleware{
		retryPolicy: DefaultPolicy(),
	}

	for _, option := range options {
		option(middleware)
	}

	return middleware
}
