package retry

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func TestConfigLoader_LoadConfig(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		expected Config
		wantErr  bool
	}{
		{
			name: "complete configuration",
			yaml: `
retry:
  database:
    enabled: true
    max_attempts: 5
    initial_delay: "200ms"
    max_delay: "10s"
    backoff_multiplier: 3.0
    retryable_errors:
      - "connection refused"
      - "timeout"
    jitter_enabled: true
  external_services:
    enabled: true
    max_attempts: 3
    initial_delay: "500ms"
    max_delay: "15s"
    backoff_multiplier: 2.0
    jitter_enabled: false
  service_operations:
    enabled: false
    max_attempts: 2
    initial_delay: "100ms"
    max_delay: "5s"
    backoff_multiplier: 1.5
    jitter_enabled: true
  circuit_breaker:
    failure_threshold: 10
    timeout: "120s"
    half_open_requests: 5
`,
			expected: Config{
				Database: Policy{
					Enabled:           true,
					MaxAttempts:       5,
					InitialDelay:      200 * time.Millisecond,
					MaxDelay:          10 * time.Second,
					BackoffMultiplier: 3.0,
					RetryableErrors:   []string{"connection refused", "timeout"},
					JitterEnabled:     true,
				},
				ExternalServices: Policy{
					Enabled:           true,
					MaxAttempts:       3,
					InitialDelay:      500 * time.Millisecond,
					MaxDelay:          15 * time.Second,
					BackoffMultiplier: 2.0,
					RetryableErrors:   []string{},
					JitterEnabled:     false,
				},
				ServiceOperations: Policy{
					Enabled:           false,
					MaxAttempts:       2,
					InitialDelay:      100 * time.Millisecond,
					MaxDelay:          5 * time.Second,
					BackoffMultiplier: 1.5,
					RetryableErrors:   []string{},
					JitterEnabled:     true,
				},
				CircuitBreaker: CircuitBreakerConfig{
					FailureThreshold: 10,
					Timeout:          120 * time.Second,
					HalfOpenRequests: 5,
				},
			},
			wantErr: false,
		},
		{
			name: "partial configuration with defaults",
			yaml: `
retry:
  database:
    enabled: true
    max_attempts: 3
`,
			expected: Config{
				Database: Policy{
					Enabled:           true,
					MaxAttempts:       3,
					InitialDelay:      100 * time.Millisecond, // From DatabasePolicy() defaults
					MaxDelay:          5 * time.Second,        // From DatabasePolicy() defaults
					BackoffMultiplier: 2.0,                    // From DatabasePolicy() defaults
					RetryableErrors:   DatabasePolicy().RetryableErrors,
					JitterEnabled:     false, // From partial config
				},
				ExternalServices:  ExternalServicePolicy(),
				ServiceOperations: DefaultConfig().ServiceOperations,
				CircuitBreaker:    DefaultCircuitBreaker(),
			},
			wantErr: false,
		},
		{
			name: "invalid configuration",
			yaml: `
retry:
  database:
    enabled: true
    max_attempts: 0
`,
			expected: Config{},
			wantErr:  true,
		},
		{
			name:     "empty configuration uses defaults",
			yaml:     "",
			expected: DefaultConfig(),
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			v.SetConfigType("yaml")
			err := v.ReadConfig(strings.NewReader(tt.yaml))
			if err != nil {
				t.Fatalf("failed to read config: %v", err)
			}

			loader := NewConfigLoader(v)
			config, err := loader.LoadConfig()

			if (err != nil) != tt.wantErr {
				t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Compare configurations
			if config.Database.Enabled != tt.expected.Database.Enabled {
				t.Errorf("Database.Enabled = %v, want %v", config.Database.Enabled, tt.expected.Database.Enabled)
			}
			if config.Database.MaxAttempts != tt.expected.Database.MaxAttempts {
				t.Errorf("Database.MaxAttempts = %v, want %v", config.Database.MaxAttempts, tt.expected.Database.MaxAttempts)
			}
			if config.Database.InitialDelay != tt.expected.Database.InitialDelay {
				t.Errorf("Database.InitialDelay = %v, want %v", config.Database.InitialDelay, tt.expected.Database.InitialDelay)
			}
			if config.Database.MaxDelay != tt.expected.Database.MaxDelay {
				t.Errorf("Database.MaxDelay = %v, want %v", config.Database.MaxDelay, tt.expected.Database.MaxDelay)
			}
			if config.Database.BackoffMultiplier != tt.expected.Database.BackoffMultiplier {
				t.Errorf("Database.BackoffMultiplier = %v, want %v", config.Database.BackoffMultiplier, tt.expected.Database.BackoffMultiplier)
			}
			if config.Database.JitterEnabled != tt.expected.Database.JitterEnabled {
				t.Errorf("Database.JitterEnabled = %v, want %v", config.Database.JitterEnabled, tt.expected.Database.JitterEnabled)
			}
			if len(config.Database.RetryableErrors) != len(tt.expected.Database.RetryableErrors) {
				t.Errorf("Database.RetryableErrors length = %v, want %v", len(config.Database.RetryableErrors), len(tt.expected.Database.RetryableErrors))
			}
		})
	}
}

func TestConfigLoader_LoadConfig_Interactive(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	yamlConfig := `
retry:
  interactive:
    enabled: true
    max_attempts: 3
    initial_delay: "300ms"
    max_delay: "3s"
    backoff_multiplier: 2.0
    retryable_errors:
      - "timeout"
    jitter_enabled: false
`
	if err := v.ReadConfig(strings.NewReader(yamlConfig)); err != nil {
		t.Fatalf("failed to read config: %v", err)
	}

	loader := NewConfigLoader(v)
	config, err := loader.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.Interactive.MaxAttempts != 3 {
		t.Errorf("expected interactive max_attempts 3, got %d", config.Interactive.MaxAttempts)
	}
	if config.Interactive.InitialDelay != 300*time.Millisecond {
		t.Errorf("expected interactive initial_delay 300ms, got %v", config.Interactive.InitialDelay)
	}
	if len(config.Interactive.RetryableErrors) != 1 || config.Interactive.RetryableErrors[0] != "timeout" {
		t.Errorf("expected interactive retryable_errors [timeout], got %v", config.Interactive.RetryableErrors)
	}
}

func TestConfigLoader_loadPolicyConfig(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		key      string
		expected *Policy
	}{
		{
			name: "complete policy config",
			yaml: `
retry:
  database:
    enabled: true
    max_attempts: 5
    initial_delay: "200ms"
    max_delay: "10s"
    backoff_multiplier: 3.0
    retryable_errors:
      - "connection refused"
      - "timeout"
    jitter_enabled: true
`,
			key: "retry.database",
			expected: &Policy{
				Enabled:           true,
				MaxAttempts:       5,
				InitialDelay:      200 * time.Millisecond,
				MaxDelay:          10 * time.Second,
				BackoffMultiplier: 3.0,
				RetryableErrors:   []string{"connection refused", "timeout"},
				JitterEnabled:     true,
			},
		},
		{
			name: "partial policy config",
			yaml: `
retry:
  database:
    enabled: true
    max_attempts: 3
`,
			key: "retry.database",
			expected: &Policy{
				Enabled:           true,
				MaxAttempts:       3,
				InitialDelay:      0,
				MaxDelay:          0,
				BackoffMultiplier: 0,
				RetryableErrors:   []string{},
				JitterEnabled:     false,
			},
		},
		{
			name:     "missing config",
			yaml:     "",
			key:      "retry.database",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			v.SetConfigType("yaml")
			err := v.ReadConfig(strings.NewReader(tt.yaml))
			if err != nil {
				t.Fatalf("failed to read config: %v", err)
			}

			loader := NewConfigLoader(v)
			policy := loader.loadPolicyConfig(tt.key)

			if tt.expected == nil {
				if policy != nil {
					t.Errorf("expected nil, got %v", policy)
				}
				return
			}

			if policy == nil {
				t.Error("expected policy, got nil")
				return
			}

			if policy.Enabled != tt.expected.Enabled {
				t.Errorf("Enabled = %v, want %v", policy.Enabled, tt.expected.Enabled)
			}
			if policy.MaxAttempts != tt.expected.MaxAttempts {
				t.Errorf("MaxAttempts = %v, want %v", policy.MaxAttempts, tt.expected.MaxAttempts)
			}
			if policy.InitialDelay != tt.expected.InitialDelay {
				t.Errorf("InitialDelay = %v, want %v", policy.InitialDelay, tt.expected.InitialDelay)
			}
			if policy.MaxDelay != tt.expected.MaxDelay {
				t.Errorf("MaxDelay = %v, want %v", policy.MaxDelay, tt.expected.MaxDelay)
			}
			if policy.BackoffMultiplier != tt.expected.BackoffMultiplier {
				t.Errorf("BackoffMultiplier = %v, want %v", policy.BackoffMultiplier, tt.expected.BackoffMultiplier)
			}
			if policy.JitterEnabled != tt.expected.JitterEnabled {
				t.Errorf("JitterEnabled = %v, want %v", policy.JitterEnabled, tt.expected.JitterEnabled)
			}
		})
	}
}

func TestConfigLoader_loadCircuitBreakerConfig(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		key      string
		expected *CircuitBreakerConfig
	}{
		{
			name: "complete circuit breaker config",
			yaml: `
retry:
  circuit_breaker:
    failure_threshold: 10
    timeout: "120s"
    half_open_requests: 5
`,
			key: "retry.circuit_breaker",
			expected: &CircuitBreakerConfig{
				FailureThreshold: 10,
				Timeout:          120 * time.Second,
				HalfOpenRequests: 5,
			},
		},
		{
			name:     "missing config",
			yaml:     "",
			key:      "retry.circuit_breaker",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			v.SetConfigType("yaml")
			err := v.ReadConfig(strings.NewReader(tt.yaml))
			if err != nil {
				t.Fatalf("failed to read config: %v", err)
			}

			loader := NewConfigLoader(v)
			config := loader.loadCircuitBreakerConfig(tt.key)

			if tt.expected == nil {
				if config != nil {
					t.Errorf("expected nil, got %v", config)
				}
				return
			}

			if config == nil {
				t.Error("expected config, got nil")
				return
			}

			if config.FailureThreshold != tt.expected.FailureThreshold {
				t.Errorf("FailureThreshold = %v, want %v", config.FailureThreshold, tt.expected.FailureThreshold)
			}
			if config.Timeout != tt.expected.Timeout {
				t.Errorf("Timeout = %v, want %v", config.Timeout, tt.expected.Timeout)
			}
			if config.HalfOpenRequests != tt.expected.HalfOpenRequests {
				t.Errorf("HalfOpenRequests = %v, want %v", config.HalfOpenRequests, tt.expected.HalfOpenRequests)
			}
		})
	}
}

func TestLoadConfigFromViper(t *testing.T) {
	yaml := `
retry:
  database:
    enabled: true
    max_attempts: 3
`

	v := viper.New()
	v.SetConfigType("yaml")
	err := v.ReadConfig(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}

	config, err := LoadConfigFromViper(v)
	if err != nil {
		t.Fatalf("LoadConfigFromViper() error = %v", err)
	}

	if !config.Database.Enabled {
		t.Error("expected database retry to be enabled")
	}

	if config.Database.MaxAttempts != 3 {
		t.Errorf("expected max attempts 3, got %d", config.Database.MaxAttempts)
	}
}

func TestSetRetryDefaults(t *testing.T) {
	v := viper.New()
	SetRetryDefaults(v)

	// Check database defaults
	if v.GetBool("retry.database.enabled") != true {
		t.Error("expected database retry to be enabled by default")
	}
	if v.GetInt("retry.database.max_attempts") != 3 {
		t.Errorf("expected database max attempts 3, got %d", v.GetInt("retry.database.max_attempts"))
	}

	// Check external services defaults
	if v.GetBool("retry.external_services.enabled") != true {
		t.Error("expected external services retry to be enabled by default")
	}
	if v.GetInt("retry.external_services.max_attempts") != 5 {
		t.Errorf("expected external services max attempts 5, got %d", v.GetInt("retry.external_services.max_attempts"))
	}

	// Check circuit breaker defaults
	if v.GetInt("retry.circuit_breaker.failure_threshold") != 5 {
		t.Errorf("expected circuit breaker failure threshold 5, got %d", v.GetInt("retry.circuit_breaker.failure_threshold"))
	}

	// Check retryable_errors lists match their source-of-truth Policy
	// functions exactly — pins the fix for the defaults drifting apart
	// (SetRetryDefaults previously hand-duplicated these lists and fell out
	// of sync with DatabasePolicy()/ExternalServicePolicy() when the latter
	// gained new entries).
	dbErrors := v.GetStringSlice("retry.database.retryable_errors")
	if !reflect.DeepEqual(dbErrors, DatabasePolicy().RetryableErrors) {
		t.Errorf("retry.database.retryable_errors default = %v, want %v (DatabasePolicy().RetryableErrors)",
			dbErrors, DatabasePolicy().RetryableErrors)
	}
	extErrors := v.GetStringSlice("retry.external_services.retryable_errors")
	if !reflect.DeepEqual(extErrors, ExternalServicePolicy().RetryableErrors) {
		t.Errorf("retry.external_services.retryable_errors default = %v, want %v (ExternalServicePolicy().RetryableErrors)",
			extErrors, ExternalServicePolicy().RetryableErrors)
	}

	// Check interactive tier defaults exist and are bounded (new tier — see
	// InteractivePolicy).
	if v.GetInt("retry.interactive.max_attempts") != 2 {
		t.Errorf("expected interactive max attempts 2, got %d", v.GetInt("retry.interactive.max_attempts"))
	}
	interactiveErrors := v.GetStringSlice("retry.interactive.retryable_errors")
	if !reflect.DeepEqual(interactiveErrors, ExternalServicePolicy().RetryableErrors) {
		t.Errorf("retry.interactive.retryable_errors default = %v, want %v", interactiveErrors, ExternalServicePolicy().RetryableErrors)
	}
}

func TestBindRetryConfig(t *testing.T) {
	v := viper.New()
	BindRetryConfig(v)

	// Test that environment variables are bound
	testCases := []struct {
		key          string
		envVar       string
		defaultValue interface{}
	}{
		{"retry.database.enabled", "RETRY_DATABASE_ENABLED", true},
		{"retry.database.max_attempts", "RETRY_DATABASE_MAX_ATTEMPTS", 3},
		{"retry.external_services.enabled", "RETRY_EXTERNAL_SERVICES_ENABLED", true},
		{"retry.circuit_breaker.failure_threshold", "RETRY_CIRCUIT_BREAKER_FAILURE_THRESHOLD", 5},
	}

	for _, tc := range testCases {
		// Set environment variable
		t.Setenv(tc.envVar, "test-value")

		// Check that the value can be retrieved
		if v.GetString(tc.key) != "test-value" {
			t.Errorf("expected %s to be bound to %s", tc.key, tc.envVar)
		}
	}
}

func TestRetryConfigFromEnvironment(t *testing.T) {
	tests := []struct {
		env      string
		expected Config
	}{
		{
			env:      "development",
			expected: DevelopmentConfig(),
		},
		{
			env:      "test",
			expected: TestingConfig(),
		},
		{
			env:      "production",
			expected: ProductionConfig(),
		},
		{
			env:      "unknown",
			expected: DefaultConfig(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.env, func(t *testing.T) {
			config := RetryConfigFromEnvironment(tt.env)

			// Compare some key fields
			if config.Database.Enabled != tt.expected.Database.Enabled {
				t.Errorf("Database.Enabled = %v, want %v", config.Database.Enabled, tt.expected.Database.Enabled)
			}
			if config.Database.MaxAttempts != tt.expected.Database.MaxAttempts {
				t.Errorf("Database.MaxAttempts = %v, want %v", config.Database.MaxAttempts, tt.expected.Database.MaxAttempts)
			}
		})
	}
}

// Benchmark tests
func BenchmarkLoadConfig(b *testing.B) {
	yaml := `
retry:
  database:
    enabled: true
    max_attempts: 3
    initial_delay: "100ms"
    max_delay: "5s"
    backoff_multiplier: 2.0
    retryable_errors:
      - "connection refused"
      - "database is locked"
      - "busy"
      - "timeout"
    jitter_enabled: true
  external_services:
    enabled: true
    max_attempts: 5
    initial_delay: "1s"
    max_delay: "30s"
    backoff_multiplier: 2.0
    retryable_errors:
      - "connection refused"
      - "no such host"
      - "timeout"
      - "temporary failure"
      - "service unavailable"
      - "too many requests"
    jitter_enabled: true
  service_operations:
    enabled: true
    max_attempts: 2
    initial_delay: "500ms"
    max_delay: "2s"
    backoff_multiplier: 1.5
    retryable_errors:
      - "connection refused"
      - "timeout"
      - "temporary failure"
    jitter_enabled: true
  circuit_breaker:
    failure_threshold: 5
    timeout: "60s"
    half_open_requests: 3
`

	v := viper.New()
	v.SetConfigType("yaml")
	err := v.ReadConfig(strings.NewReader(yaml))
	if err != nil {
		b.Fatalf("failed to read config: %v", err)
	}

	loader := NewConfigLoader(v)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := loader.LoadConfig()
		if err != nil {
			b.Fatalf("LoadConfig() error = %v", err)
		}
	}
}

func BenchmarkSetRetryDefaults(b *testing.B) {
	for i := 0; i < b.N; i++ {
		v := viper.New()
		SetRetryDefaults(v)
	}
}
