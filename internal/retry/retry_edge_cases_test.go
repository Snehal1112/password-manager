package retry_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/retry"
)

// --- config.go: Merge, ForEnvironment, ConfigProvider, LoadConfigFromYAML/JSON, ToYAML/ToJSON, ExampleYAML/JSON ---

func TestConfig_Merge(t *testing.T) {
	base := retry.DefaultConfig()
	other := retry.TestingConfig()

	merged := base.Merge(other)

	// TestingConfig has smaller max attempts; confirm merge takes the other config.
	if merged.Database.MaxAttempts != other.Database.MaxAttempts {
		t.Errorf("expected merged database max attempts %d, got %d", other.Database.MaxAttempts, merged.Database.MaxAttempts)
	}
	if merged.CircuitBreaker.FailureThreshold != other.CircuitBreaker.FailureThreshold {
		t.Errorf("expected merged circuit breaker threshold %d, got %d", other.CircuitBreaker.FailureThreshold, merged.CircuitBreaker.FailureThreshold)
	}
}

func TestConfig_Merge_DisabledPoliciesNotOverridden(t *testing.T) {
	base := retry.DefaultConfig()
	other := retry.Config{
		// Leave Database and ExternalServices disabled so base values should remain.
		Database:          retry.Policy{Enabled: false},
		ExternalServices:  retry.Policy{Enabled: false},
		ServiceOperations: retry.Policy{Enabled: false},
		CircuitBreaker:    retry.CircuitBreakerConfig{FailureThreshold: 99, Timeout: time.Second, HalfOpenRequests: 1},
	}

	merged := base.Merge(other)

	// Disabled policies in "other" should not override base.
	if merged.Database.MaxAttempts != base.Database.MaxAttempts {
		t.Errorf("disabled policy should not override; expected %d, got %d", base.Database.MaxAttempts, merged.Database.MaxAttempts)
	}
	// CircuitBreaker is always merged.
	if merged.CircuitBreaker.FailureThreshold != 99 {
		t.Errorf("circuit breaker should always merge; expected 99, got %d", merged.CircuitBreaker.FailureThreshold)
	}
}

func TestForEnvironment(t *testing.T) {
	cases := []struct {
		env          string
		wantAttempts int
	}{
		{"production", retry.ProductionConfig().Database.MaxAttempts},
		{"prod", retry.ProductionConfig().Database.MaxAttempts},
		{"development", retry.DevelopmentConfig().Database.MaxAttempts},
		{"dev", retry.DevelopmentConfig().Database.MaxAttempts},
		{"testing", retry.TestingConfig().Database.MaxAttempts},
		{"test", retry.TestingConfig().Database.MaxAttempts},
		{"unknown", retry.DefaultConfig().Database.MaxAttempts},
		{"", retry.DefaultConfig().Database.MaxAttempts},
	}
	for _, tc := range cases {
		got := retry.ForEnvironment(tc.env)
		if got.Database.MaxAttempts != tc.wantAttempts {
			t.Errorf("ForEnvironment(%q): got max attempts %d, want %d", tc.env, got.Database.MaxAttempts, tc.wantAttempts)
		}
	}
}

func TestNewConfigProvider(t *testing.T) {
	cfg := retry.DefaultConfig()
	p := retry.NewConfigProvider(cfg)

	if p.GetDatabasePolicy().MaxAttempts != cfg.Database.MaxAttempts {
		t.Errorf("GetDatabasePolicy mismatch")
	}
	if p.GetExternalServicePolicy().MaxAttempts != cfg.ExternalServices.MaxAttempts {
		t.Errorf("GetExternalServicePolicy mismatch")
	}
	if p.GetServiceOperationsPolicy().MaxAttempts != cfg.ServiceOperations.MaxAttempts {
		t.Errorf("GetServiceOperationsPolicy mismatch")
	}
	if p.GetCircuitBreakerConfig().FailureThreshold != cfg.CircuitBreaker.FailureThreshold {
		t.Errorf("GetCircuitBreakerConfig mismatch")
	}
}

func TestLoadConfigFromYAML_Valid(t *testing.T) {
	// Use ToYAML to get a valid serialised form and round-trip through LoadConfigFromYAML.
	original := retry.DefaultConfig()
	data, err := original.ToYAML()
	if err != nil {
		t.Fatalf("ToYAML failed: %v", err)
	}

	cfg, err := retry.LoadConfigFromYAML(data)
	if err != nil {
		t.Fatalf("LoadConfigFromYAML returned unexpected error: %v", err)
	}
	if !cfg.Database.Enabled {
		t.Error("expected database enabled")
	}
	if cfg.Database.MaxAttempts != original.Database.MaxAttempts {
		t.Errorf("expected max attempts %d, got %d", original.Database.MaxAttempts, cfg.Database.MaxAttempts)
	}
}

func TestLoadConfigFromYAML_Invalid(t *testing.T) {
	// Malformed YAML.
	_, err := retry.LoadConfigFromYAML([]byte("{invalid yaml{{"))
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestLoadConfigFromJSON_Valid(t *testing.T) {
	data, err := retry.DefaultConfig().ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	cfg, err := retry.LoadConfigFromJSON(data)
	if err != nil {
		t.Fatalf("LoadConfigFromJSON returned unexpected error: %v", err)
	}
	if cfg.Database.MaxAttempts != retry.DefaultConfig().Database.MaxAttempts {
		t.Errorf("expected max attempts %d, got %d", retry.DefaultConfig().Database.MaxAttempts, cfg.Database.MaxAttempts)
	}
}

func TestLoadConfigFromJSON_Invalid(t *testing.T) {
	_, err := retry.LoadConfigFromJSON([]byte("{not-json"))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestConfig_ToYAML(t *testing.T) {
	cfg := retry.DefaultConfig()
	data, err := cfg.ToYAML()
	if err != nil {
		t.Fatalf("ToYAML returned error: %v", err)
	}
	if len(data) == 0 {
		t.Error("ToYAML returned empty data")
	}
}

func TestConfig_ToJSON(t *testing.T) {
	cfg := retry.DefaultConfig()
	data, err := cfg.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON returned error: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("ToJSON returned invalid JSON: %v", err)
	}
}

func TestExampleYAML(t *testing.T) {
	s := retry.ExampleYAML()
	if len(s) == 0 {
		t.Error("ExampleYAML returned empty string")
	}
}

func TestExampleJSON(t *testing.T) {
	s := retry.ExampleJSON()
	if len(s) == 0 {
		t.Error("ExampleJSON returned empty string")
	}
}

// --- retry.go: retryableError.Error(), recordSuccess path ---

func TestRetryableError_Error(t *testing.T) {
	original := errors.New("something went wrong")
	wrapped := retry.Retryable(original)
	if wrapped.Error() != original.Error() {
		t.Errorf("expected error string %q, got %q", original.Error(), wrapped.Error())
	}
}

func TestNonRetryable_NilInput(t *testing.T) {
	result := retry.NonRetryable(nil)
	if result != nil {
		t.Errorf("expected nil from NonRetryable(nil), got %v", result)
	}
}

func TestRetryable_NilInput(t *testing.T) {
	result := retry.Retryable(nil)
	if result != nil {
		t.Errorf("expected nil from Retryable(nil), got %v", result)
	}
}

func TestCircuitBreaker_RecordSuccess(t *testing.T) {
	cfg := retry.CircuitBreakerConfig{
		FailureThreshold: 2,
		Timeout:          10 * time.Millisecond,
		HalfOpenRequests: 2,
	}
	cb := retry.NewCircuitBreaker(cfg)

	// Cause one failure to increment the counter.
	_ = cb.Execute(func() error { return errors.New("fail") })

	// Now succeed: this should call recordSuccess and reset the failure count.
	err := cb.Execute(func() error { return nil })
	if err != nil {
		t.Errorf("expected success, got %v", err)
	}

	// One more failure should not immediately open the circuit (counter was reset).
	_ = cb.Execute(func() error { return errors.New("fail") })
	if cb.GetState() != retry.StateClosed {
		t.Errorf("circuit should still be closed after reset + 1 failure, got state %v", cb.GetState())
	}
}

func TestWithExponentialBackoff_NonRetryableError(t *testing.T) {
	policy := retry.Policy{
		Enabled:           true,
		MaxAttempts:       5,
		InitialDelay:      1 * time.Millisecond,
		MaxDelay:          10 * time.Millisecond,
		BackoffMultiplier: 2.0,
		RetryableErrors:   []string{"temporary"},
	}

	attempts := 0
	err := retry.WithExponentialBackoff(context.Background(), policy, func() error {
		attempts++
		return errors.New("permanent failure")
	})

	if !errors.Is(err, retry.ErrNonRetryable) {
		t.Errorf("expected ErrNonRetryable, got %v", err)
	}
	if attempts != 1 {
		t.Errorf("expected exactly 1 attempt for non-retryable error, got %d", attempts)
	}
}

func TestWithExponentialBackoffResult_NonRetryableError(t *testing.T) {
	policy := retry.Policy{
		Enabled:           true,
		MaxAttempts:       5,
		InitialDelay:      1 * time.Millisecond,
		MaxDelay:          10 * time.Millisecond,
		BackoffMultiplier: 2.0,
		RetryableErrors:   []string{"temporary"},
	}

	attempts := 0
	_, err := retry.WithExponentialBackoffResult(context.Background(), policy, func() (string, error) {
		attempts++
		return "", errors.New("permanent failure")
	})

	if !errors.Is(err, retry.ErrNonRetryable) {
		t.Errorf("expected ErrNonRetryable, got %v", err)
	}
	if attempts != 1 {
		t.Errorf("expected exactly 1 attempt for non-retryable error, got %d", attempts)
	}
}

func TestWithExponentialBackoffResult_ContextCancel(t *testing.T) {
	policy := retry.Policy{
		Enabled:           true,
		MaxAttempts:       10,
		InitialDelay:      50 * time.Millisecond,
		MaxDelay:          500 * time.Millisecond,
		BackoffMultiplier: 2.0,
		RetryableErrors:   []string{"retry me"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	_, err := retry.WithExponentialBackoffResult(ctx, policy, func() (string, error) {
		return "", errors.New("retry me")
	})

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestWithExponentialBackoff_JitterEnabled(t *testing.T) {
	policy := retry.Policy{
		Enabled:           true,
		MaxAttempts:       2,
		InitialDelay:      1 * time.Millisecond,
		MaxDelay:          10 * time.Millisecond,
		BackoffMultiplier: 2.0,
		JitterEnabled:     true,
		RetryableErrors:   []string{"retry"},
	}

	attempts := 0
	err := retry.WithExponentialBackoff(context.Background(), policy, func() error {
		attempts++
		if attempts < 2 {
			return errors.New("retry")
		}
		return nil
	})
	if err != nil {
		t.Errorf("expected success, got %v", err)
	}
}

// --- repository_wrapper.go ---

// mockRepo implements retry.Repository[string] for testing.
type mockRepo struct {
	createErr error
	readVal   string
	readErr   error
	updateErr error
	deleteErr error
	calls     int32
}

func (m *mockRepo) Create(_ context.Context, _ string) error {
	atomic.AddInt32(&m.calls, 1)
	return m.createErr
}

func (m *mockRepo) Read(_ context.Context, _ uuid.UUID) (string, error) {
	atomic.AddInt32(&m.calls, 1)
	return m.readVal, m.readErr
}

func (m *mockRepo) Update(_ context.Context, _ string) error {
	atomic.AddInt32(&m.calls, 1)
	return m.updateErr
}

func (m *mockRepo) Delete(_ context.Context, _ uuid.UUID) error {
	atomic.AddInt32(&m.calls, 1)
	return m.deleteErr
}

func testPolicy() retry.Policy {
	return retry.Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      1 * time.Millisecond,
		MaxDelay:          10 * time.Millisecond,
		BackoffMultiplier: 2.0,
		RetryableErrors:   []string{"connection refused"},
	}
}

func TestRetryableRepository_Create_Success(t *testing.T) {
	repo := &mockRepo{}
	rr := retry.NewRetryableRepository[string](repo, testPolicy())

	err := rr.Create(context.Background(), "test")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if atomic.LoadInt32(&repo.calls) != 1 {
		t.Errorf("expected 1 call, got %d", repo.calls)
	}
}

func TestRetryableRepository_Create_Retry(t *testing.T) {
	// Use a custom repo that fails once then succeeds.
	failOnce := &failOnceRepo{failErr: errors.New("connection refused")}
	rr := retry.NewRetryableRepository[string](failOnce, testPolicy())
	err := rr.Create(context.Background(), "test")
	if err != nil {
		t.Errorf("expected success after retry, got %v", err)
	}
	if failOnce.calls != 2 {
		t.Errorf("expected 2 calls, got %d", failOnce.calls)
	}
}

func TestRetryableRepository_Read_Success(t *testing.T) {
	repo := &mockRepo{readVal: "result"}
	rr := retry.NewRetryableRepository[string](repo, testPolicy())

	val, err := rr.Read(context.Background(), uuid.New())
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if val != "result" {
		t.Errorf("expected 'result', got %q", val)
	}
}

func TestRetryableRepository_Update_Success(t *testing.T) {
	repo := &mockRepo{}
	rr := retry.NewRetryableRepository[string](repo, testPolicy())

	err := rr.Update(context.Background(), "test")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestRetryableRepository_Delete_Success(t *testing.T) {
	repo := &mockRepo{}
	rr := retry.NewRetryableRepository[string](repo, testPolicy())

	err := rr.Delete(context.Background(), uuid.New())
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

// failOnceRepo succeeds on the second call.
type failOnceRepo struct {
	failErr error
	calls   int
}

func (r *failOnceRepo) Create(_ context.Context, _ string) error {
	r.calls++
	if r.calls == 1 {
		return r.failErr
	}
	return nil
}

func (r *failOnceRepo) Read(_ context.Context, _ uuid.UUID) (string, error) {
	r.calls++
	if r.calls == 1 {
		return "", r.failErr
	}
	return "ok", nil
}

func (r *failOnceRepo) Update(_ context.Context, _ string) error {
	r.calls++
	if r.calls == 1 {
		return r.failErr
	}
	return nil
}

func (r *failOnceRepo) Delete(_ context.Context, _ uuid.UUID) error {
	r.calls++
	if r.calls == 1 {
		return r.failErr
	}
	return nil
}

// mockTransactionRepo implements retry.TransactionRepository[string].
type mockTransactionRepo struct {
	mockRepo
	beginErr error
}

func (m *mockTransactionRepo) BeginTx(_ context.Context) (retry.Transaction[string], error) {
	if m.beginErr != nil {
		return nil, m.beginErr
	}
	return &mockTransaction{}, nil
}

// mockTransaction implements retry.Transaction[string].
type mockTransaction struct {
	commitErr   error
	rollbackErr error
}

func (t *mockTransaction) Create(_ context.Context, _ string) error    { return nil }
func (t *mockTransaction) Update(_ context.Context, _ string) error    { return nil }
func (t *mockTransaction) Delete(_ context.Context, _ uuid.UUID) error { return nil }
func (t *mockTransaction) Commit() error                               { return t.commitErr }
func (t *mockTransaction) Rollback() error                             { return t.rollbackErr }

func TestRetryableTransactionRepository_CRUD(t *testing.T) {
	repo := &mockTransactionRepo{}
	rtr := retry.NewRetryableTransactionRepository[string](repo, testPolicy())

	ctx := context.Background()

	if err := rtr.Create(ctx, "v"); err != nil {
		t.Errorf("Create: %v", err)
	}
	if _, err := rtr.Read(ctx, uuid.New()); err != nil {
		t.Errorf("Read: %v", err)
	}
	if err := rtr.Update(ctx, "v"); err != nil {
		t.Errorf("Update: %v", err)
	}
	if err := rtr.Delete(ctx, uuid.New()); err != nil {
		t.Errorf("Delete: %v", err)
	}
}

func TestRetryableTransactionRepository_BeginTx(t *testing.T) {
	repo := &mockTransactionRepo{}
	rtr := retry.NewRetryableTransactionRepository[string](repo, testPolicy())

	tx, err := rtr.BeginTx(context.Background())
	if err != nil {
		t.Fatalf("BeginTx failed: %v", err)
	}
	if tx == nil {
		t.Fatal("expected non-nil transaction")
	}
}

func TestRetryableTransactionRepository_CommitRollback(t *testing.T) {
	repo := &mockTransactionRepo{}
	rtr := retry.NewRetryableTransactionRepository[string](repo, testPolicy())

	tx, err := rtr.BeginTx(context.Background())
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}

	if err := tx.Commit(); err != nil {
		t.Errorf("Commit: %v", err)
	}

	// Begin another transaction to test Rollback.
	tx2, err := rtr.BeginTx(context.Background())
	if err != nil {
		t.Fatalf("BeginTx2: %v", err)
	}
	if err := tx2.Rollback(); err != nil {
		t.Errorf("Rollback: %v", err)
	}
}

func TestRetryableTransactionRepository_TransactionOps(t *testing.T) {
	repo := &mockTransactionRepo{}
	rtr := retry.NewRetryableTransactionRepository[string](repo, testPolicy())

	tx, err := rtr.BeginTx(context.Background())
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}

	ctx := context.Background()
	if err := tx.Create(ctx, "v"); err != nil {
		t.Errorf("tx.Create: %v", err)
	}
	if err := tx.Update(ctx, "v"); err != nil {
		t.Errorf("tx.Update: %v", err)
	}
	if err := tx.Delete(ctx, uuid.New()); err != nil {
		t.Errorf("tx.Delete: %v", err)
	}
}

// --- RetryableHTTPClient ---

func TestRetryableHTTPClient_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	policy := retry.Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      1 * time.Millisecond,
		MaxDelay:          10 * time.Millisecond,
		BackoffMultiplier: 2.0,
		RetryableStatuses: []int{500, 503},
	}
	cb := retry.NewCircuitBreaker(retry.DefaultCircuitBreaker())
	client := retry.NewRetryableHTTPClient(http.DefaultClient, policy, cb)

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestRetryableHTTPClient_NoCircuitBreaker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	policy := retry.Policy{
		Enabled:           true,
		MaxAttempts:       2,
		InitialDelay:      1 * time.Millisecond,
		MaxDelay:          10 * time.Millisecond,
		BackoffMultiplier: 2.0,
	}
	client := retry.NewRetryableHTTPClient(http.DefaultClient, policy, nil)

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
}

func TestRetryableHTTPClient_Disabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	policy := retry.Policy{Enabled: false}
	client := retry.NewRetryableHTTPClient(http.DefaultClient, policy, nil)

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
}

func TestRetryableHTTPClient_Disabled_WithCircuitBreaker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	policy := retry.Policy{Enabled: false}
	cb := retry.NewCircuitBreaker(retry.DefaultCircuitBreaker())
	client := retry.NewRetryableHTTPClient(http.DefaultClient, policy, cb)

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
}

func TestRetryableHTTPClient_RetryOn500(t *testing.T) {
	var callCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&callCount, 1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	policy := retry.Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      1 * time.Millisecond,
		MaxDelay:          10 * time.Millisecond,
		BackoffMultiplier: 2.0,
		RetryableStatuses: []int{500},
	}
	client := retry.NewRetryableHTTPClient(http.DefaultClient, policy, nil)

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if atomic.LoadInt32(&callCount) != 2 {
		t.Errorf("expected 2 calls, got %d", callCount)
	}
}

func TestRetryableHTTPClient_ContextCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	policy := retry.Policy{
		Enabled:           true,
		MaxAttempts:       10,
		InitialDelay:      50 * time.Millisecond,
		MaxDelay:          500 * time.Millisecond,
		BackoffMultiplier: 2.0,
		RetryableStatuses: []int{500},
	}
	client := retry.NewRetryableHTTPClient(http.DefaultClient, policy, nil)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	_, err := client.Do(req)
	if err == nil {
		t.Error("expected error due to context cancellation")
	}
}

// --- ConnectionWrapper ---

func TestConnectionWrapper_Execute(t *testing.T) {
	cw := retry.NewConnectionWrapper(testPolicy())

	err := cw.Execute(context.Background(), func() error {
		return nil
	})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestConnectionWrapper_ExecuteString(t *testing.T) {
	cw := retry.NewConnectionWrapper(testPolicy())

	val, err := cw.ExecuteString(context.Background(), func() (string, error) {
		return "hello", nil
	})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if val != "hello" {
		t.Errorf("expected 'hello', got %q", val)
	}
}

func TestConnectionWrapper_ExecuteInt(t *testing.T) {
	cw := retry.NewConnectionWrapper(testPolicy())

	val, err := cw.ExecuteInt(context.Background(), func() (int, error) {
		return 42, nil
	})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if val != 42 {
		t.Errorf("expected 42, got %d", val)
	}
}

func TestConnectionWrapper_ExecuteBool(t *testing.T) {
	cw := retry.NewConnectionWrapper(testPolicy())

	val, err := cw.ExecuteBool(context.Background(), func() (bool, error) {
		return true, nil
	})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !val {
		t.Error("expected true")
	}
}

// --- LoggingMetricsCollector ---

type mockLogger struct {
	infoCalls int
}

func (l *mockLogger) Info(msg string, keysAndValues ...interface{}) {
	l.infoCalls++
}

func (l *mockLogger) Error(msg string, keysAndValues ...interface{}) {}

func TestLoggingMetricsCollector(t *testing.T) {
	logger := &mockLogger{}
	collector := retry.NewLoggingMetricsCollector(logger)

	collector.RecordRetryAttempt("test-op", 0, true)
	collector.RecordRetryAttempt("test-op", 1, false)
	collector.RecordCircuitBreakerStateChange("test-op", retry.StateClosed, retry.StateOpen)

	if logger.infoCalls != 3 {
		t.Errorf("expected 3 info calls, got %d", logger.infoCalls)
	}
}

// --- CircuitState.String ---

func TestCircuitState_String(t *testing.T) {
	cases := []struct {
		state retry.CircuitState
		want  string
	}{
		{retry.StateClosed, "closed"},
		{retry.StateOpen, "open"},
		{retry.StateHalfOpen, "half-open"},
		{retry.CircuitState(99), "unknown"},
	}
	for _, tc := range cases {
		got := tc.state.String()
		if got != tc.want {
			t.Errorf("CircuitState(%d).String() = %q, want %q", tc.state, got, tc.want)
		}
	}
}

// --- middleware.go: responseRecorder.Header ---

func TestResponseRecorder_Header(t *testing.T) {
	policy := retry.Policy{
		Enabled:           true,
		MaxAttempts:       1,
		InitialDelay:      1 * time.Millisecond,
		MaxDelay:          10 * time.Millisecond,
		BackoffMultiplier: 2.0,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write a custom header to exercise responseRecorder.Header().
		w.Header().Set("X-Custom", "value")
		w.WriteHeader(http.StatusOK)
	})

	middleware := retry.NewHTTPMiddleware(policy, nil)
	server := httptest.NewServer(middleware.Middleware(handler))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// --- Config.Validate edge cases ---

func TestConfig_Validate_InvalidDatabase(t *testing.T) {
	cfg := retry.DefaultConfig()
	cfg.Database.MaxAttempts = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for zero max attempts")
	}
}

func TestConfig_Validate_InvalidCircuitBreaker(t *testing.T) {
	cfg := retry.DefaultConfig()
	cfg.CircuitBreaker.FailureThreshold = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for zero circuit breaker threshold")
	}
}

func TestConfig_Validate_MaxDelayLessThanInitial(t *testing.T) {
	cfg := retry.DefaultConfig()
	cfg.Database.MaxDelay = 1 * time.Millisecond
	cfg.Database.InitialDelay = 100 * time.Millisecond
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for max_delay < initial_delay")
	}
}

func TestConfig_Validate_LowBackoffMultiplier(t *testing.T) {
	cfg := retry.DefaultConfig()
	cfg.Database.BackoffMultiplier = 0.5
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for backoff_multiplier < 1.0")
	}
}

func TestConfig_Validate_InvalidCircuitBreakerTimeout(t *testing.T) {
	cfg := retry.DefaultConfig()
	cfg.CircuitBreaker.Timeout = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for zero circuit breaker timeout")
	}
}

func TestConfig_Validate_InvalidCircuitBreakerHalfOpen(t *testing.T) {
	cfg := retry.DefaultConfig()
	cfg.CircuitBreaker.HalfOpenRequests = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for zero half_open_requests")
	}
}
