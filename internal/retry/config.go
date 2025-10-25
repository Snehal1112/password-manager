package retry

import (
	"encoding/json"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds retry configuration for different types of operations.
type Config struct {
	Database         Policy           `yaml:"database" json:"database"`
	ExternalServices Policy           `yaml:"external_services" json:"external_services"`
	ServiceOperations Policy           `yaml:"service_operations" json:"service_operations"`
	CircuitBreaker   CircuitBreakerConfig `yaml:"circuit_breaker" json:"circuit_breaker"`
}

// DefaultConfig returns a default retry configuration.
func DefaultConfig() Config {
	return Config{
		Database:         DatabasePolicy(),
		ExternalServices: ExternalServicePolicy(),
		ServiceOperations: Policy{
			Enabled:           true,
			MaxAttempts:       2,
			InitialDelay:      500 * time.Millisecond,
			MaxDelay:          2 * time.Second,
			BackoffMultiplier: 1.5,
			RetryableErrors: []string{
				"connection refused",
				"timeout",
				"temporary failure",
			},
			JitterEnabled: true,
		},
		CircuitBreaker: DefaultCircuitBreaker(),
	}
}

// DevelopmentConfig returns a retry configuration optimized for development.
func DevelopmentConfig() Config {
	return Config{
		Database: Policy{
			Enabled:           true,
			MaxAttempts:       2,
			InitialDelay:      50 * time.Millisecond,
			MaxDelay:          1 * time.Second,
			BackoffMultiplier: 2.0,
			RetryableErrors:   DatabasePolicy().RetryableErrors,
			JitterEnabled:     true,
		},
		ExternalServices: Policy{
			Enabled:           true,
			MaxAttempts:       3,
			InitialDelay:      100 * time.Millisecond,
			MaxDelay:          5 * time.Second,
			BackoffMultiplier: 2.0,
			RetryableErrors:   ExternalServicePolicy().RetryableErrors,
			JitterEnabled:     true,
		},
		ServiceOperations: Policy{
			Enabled:           true,
			MaxAttempts:       2,
			InitialDelay:      100 * time.Millisecond,
			MaxDelay:          1 * time.Second,
			BackoffMultiplier: 1.5,
			RetryableErrors:   DefaultConfig().ServiceOperations.RetryableErrors,
			JitterEnabled:     true,
		},
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold:  3,
			Timeout:           30 * time.Second,
			HalfOpenRequests:  2,
		},
	}
}

// ProductionConfig returns a retry configuration optimized for production.
func ProductionConfig() Config {
	return Config{
		Database: Policy{
			Enabled:           true,
			MaxAttempts:       3,
			InitialDelay:      100 * time.Millisecond,
			MaxDelay:          5 * time.Second,
			BackoffMultiplier: 2.0,
			RetryableErrors:   DatabasePolicy().RetryableErrors,
			JitterEnabled:     true,
		},
		ExternalServices: Policy{
			Enabled:           true,
			MaxAttempts:       5,
			InitialDelay:      1 * time.Second,
			MaxDelay:          30 * time.Second,
			BackoffMultiplier: 2.0,
			RetryableErrors:   ExternalServicePolicy().RetryableErrors,
			JitterEnabled:     true,
		},
		ServiceOperations: Policy{
			Enabled:           true,
			MaxAttempts:       2,
			InitialDelay:      500 * time.Millisecond,
			MaxDelay:          5 * time.Second,
			BackoffMultiplier: 2.0,
			RetryableErrors:   DefaultConfig().ServiceOperations.RetryableErrors,
			JitterEnabled:     true,
		},
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold:  5,
			Timeout:           60 * time.Second,
			HalfOpenRequests:  3,
		},
	}
}

// TestingConfig returns a retry configuration optimized for testing.
func TestingConfig() Config {
	return Config{
		Database: Policy{
			Enabled:           true,
			MaxAttempts:       2,
			InitialDelay:      1 * time.Millisecond,
			MaxDelay:          10 * time.Millisecond,
			BackoffMultiplier: 2.0,
			RetryableErrors:   DatabasePolicy().RetryableErrors,
			JitterEnabled:     false,
		},
		ExternalServices: Policy{
			Enabled:           true,
			MaxAttempts:       2,
			InitialDelay:      1 * time.Millisecond,
			MaxDelay:          10 * time.Millisecond,
			BackoffMultiplier: 2.0,
			RetryableErrors:   ExternalServicePolicy().RetryableErrors,
			JitterEnabled:     false,
		},
		ServiceOperations: Policy{
			Enabled:           true,
			MaxAttempts:       2,
			InitialDelay:      1 * time.Millisecond,
			MaxDelay:          10 * time.Millisecond,
			BackoffMultiplier: 1.5,
			RetryableErrors:   DefaultConfig().ServiceOperations.RetryableErrors,
			JitterEnabled:     false,
		},
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold:  2,
			Timeout:           100 * time.Millisecond,
			HalfOpenRequests:  1,
		},
	}
}

// Validate checks if the retry configuration is valid.
func (c Config) Validate() error {
	if err := validatePolicy(c.Database, "database"); err != nil {
		return err
	}
	if err := validatePolicy(c.ExternalServices, "external_services"); err != nil {
		return err
	}
	if err := validatePolicy(c.ServiceOperations, "service_operations"); err != nil {
		return err
	}
	if err := validateCircuitBreakerConfig(c.CircuitBreaker); err != nil {
		return err
	}
	return nil
}

func validatePolicy(policy Policy, name string) error {
	if !policy.Enabled {
		return nil
	}

	if policy.MaxAttempts < 1 {
		return fmt.Errorf("%s policy: max_attempts must be at least 1", name)
	}

	if policy.InitialDelay < 0 {
		return fmt.Errorf("%s policy: initial_delay must be non-negative", name)
	}

	if policy.MaxDelay < policy.InitialDelay {
		return fmt.Errorf("%s policy: max_delay must be greater than or equal to initial_delay", name)
	}

	if policy.BackoffMultiplier < 1.0 {
		return fmt.Errorf("%s policy: backoff_multiplier must be at least 1.0", name)
	}

	return nil
}

func validateCircuitBreakerConfig(config CircuitBreakerConfig) error {
	if config.FailureThreshold < 1 {
		return fmt.Errorf("circuit_breaker: failure_threshold must be at least 1")
	}

	if config.Timeout <= 0 {
		return fmt.Errorf("circuit_breaker: timeout must be positive")
	}

	if config.HalfOpenRequests < 1 {
		return fmt.Errorf("circuit_breaker: half_open_requests must be at least 1")
	}

	return nil
}

// Merge combines two retry configurations, with the other config taking precedence.
func (c Config) Merge(other Config) Config {
	result := c

	if other.Database.Enabled {
		result.Database = other.Database
	}

	if other.ExternalServices.Enabled {
		result.ExternalServices = other.ExternalServices
	}

	if other.ServiceOperations.Enabled {
		result.ServiceOperations = other.ServiceOperations
	}

	// Circuit breaker config is always merged
	result.CircuitBreaker = other.CircuitBreaker

	return result
}

// ForEnvironment returns the appropriate retry configuration for the given environment.
func ForEnvironment(env string) Config {
	switch env {
	case "prod", "production":
		return ProductionConfig()
	case "dev", "development":
		return DevelopmentConfig()
	case "test", "testing":
		return TestingConfig()
	default:
		return DefaultConfig()
	}
}

// RetryConfigProvider provides retry configuration for different components.
type RetryConfigProvider interface {
	GetDatabasePolicy() Policy
	GetExternalServicePolicy() Policy
	GetServiceOperationsPolicy() Policy
	GetCircuitBreakerConfig() CircuitBreakerConfig
}

// ConfigProvider implements RetryConfigProvider.
type ConfigProvider struct {
	config Config
}

// NewConfigProvider creates a new retry configuration provider.
func NewConfigProvider(config Config) *ConfigProvider {
	return &ConfigProvider{config: config}
}

// GetDatabasePolicy returns the database retry policy.
func (p *ConfigProvider) GetDatabasePolicy() Policy {
	return p.config.Database
}

// GetExternalServicePolicy returns the external service retry policy.
func (p *ConfigProvider) GetExternalServicePolicy() Policy {
	return p.config.ExternalServices
}

// GetServiceOperationsPolicy returns the service operations retry policy.
func (p *ConfigProvider) GetServiceOperationsPolicy() Policy {
	return p.config.ServiceOperations
}

// GetCircuitBreakerConfig returns the circuit breaker configuration.
func (p *ConfigProvider) GetCircuitBreakerConfig() CircuitBreakerConfig {
	return p.config.CircuitBreaker
}

// LoadConfigFromYAML loads retry configuration from YAML data.
func LoadConfigFromYAML(data []byte) (Config, error) {
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("failed to unmarshal retry config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid retry config: %w", err)
	}

	return config, nil
}

// LoadConfigFromJSON loads retry configuration from JSON data.
func LoadConfigFromJSON(data []byte) (Config, error) {
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("failed to unmarshal retry config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid retry config: %w", err)
	}

	return config, nil
}

// ToYAML converts the configuration to YAML format.
func (c Config) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// ToJSON converts the configuration to JSON format.
func (c Config) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// ExampleYAML returns an example YAML configuration.
func ExampleYAML() string {
	return `
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
}

// ExampleJSON returns an example JSON configuration.
func ExampleJSON() string {
	return `{
  "database": {
    "enabled": true,
    "max_attempts": 3,
    "initial_delay": "100ms",
    "max_delay": "5s",
    "backoff_multiplier": 2.0,
    "retryable_errors": [
      "connection refused",
      "database is locked",
      "busy",
      "timeout"
    ],
    "jitter_enabled": true
  },
  "external_services": {
    "enabled": true,
    "max_attempts": 5,
    "initial_delay": "1s",
    "max_delay": "30s",
    "backoff_multiplier": 2.0,
    "retryable_errors": [
      "connection refused",
      "no such host",
      "timeout",
      "temporary failure",
      "service unavailable",
      "too many requests"
    ],
    "jitter_enabled": true
  },
  "service_operations": {
    "enabled": true,
    "max_attempts": 2,
    "initial_delay": "500ms",
    "max_delay": "2s",
    "backoff_multiplier": 1.5,
    "retryable_errors": [
      "connection refused",
      "timeout",
      "temporary failure"
    ],
    "jitter_enabled": true
  },
  "circuit_breaker": {
    "failure_threshold": 5,
    "timeout": "60s",
    "half_open_requests": 3
  }
}`
}