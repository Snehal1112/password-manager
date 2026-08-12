package retry

import (
	"fmt"

	"github.com/spf13/viper"
)

// ConfigLoader provides retry configuration loading from viper.
type ConfigLoader struct {
	viper *viper.Viper
}

// NewConfigLoader creates a new retry configuration loader.
func NewConfigLoader(v *viper.Viper) *ConfigLoader {
	return &ConfigLoader{viper: v}
}

// LoadConfig loads retry configuration from viper.
func (l *ConfigLoader) LoadConfig() (Config, error) {
	var config Config

	// Set default values
	config = DefaultConfig()

	// Load database retry configuration
	if l.viper.IsSet("retry.database") {
		dbConfig := l.loadPolicyConfig("retry.database")
		if dbConfig != nil {
			// Merge with defaults to ensure required fields are set
			config.Database = mergePolicyWithDefaults(*dbConfig, DatabasePolicy())
		}
	}

	// Load external services retry configuration
	if l.viper.IsSet("retry.external_services") {
		externalConfig := l.loadPolicyConfig("retry.external_services")
		if externalConfig != nil {
			// Merge with defaults to ensure required fields are set
			config.ExternalServices = mergePolicyWithDefaults(*externalConfig, ExternalServicePolicy())
		}
	}

	// Load service operations retry configuration
	if l.viper.IsSet("retry.service_operations") {
		serviceConfig := l.loadPolicyConfig("retry.service_operations")
		if serviceConfig != nil {
			// Merge with defaults to ensure required fields are set
			config.ServiceOperations = mergePolicyWithDefaults(*serviceConfig, DefaultConfig().ServiceOperations)
		}
	}

	// Load circuit breaker configuration
	if l.viper.IsSet("retry.circuit_breaker") {
		cbConfig := l.loadCircuitBreakerConfig("retry.circuit_breaker")
		if cbConfig != nil {
			config.CircuitBreaker = *cbConfig
		}
	}

	// Validate the configuration
	if err := config.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid retry configuration: %w", err)
	}

	return config, nil
}

// loadPolicyConfig loads a retry policy configuration from viper.
func (l *ConfigLoader) loadPolicyConfig(key string) *Policy {
	if !l.viper.IsSet(key) {
		return nil
	}

	policy := Policy{
		Enabled:           l.viper.GetBool(key + ".enabled"),
		MaxAttempts:       l.viper.GetInt(key + ".max_attempts"),
		InitialDelay:      l.viper.GetDuration(key + ".initial_delay"),
		MaxDelay:          l.viper.GetDuration(key + ".max_delay"),
		BackoffMultiplier: l.viper.GetFloat64(key + ".backoff_multiplier"),
		JitterEnabled:     l.viper.GetBool(key + ".jitter_enabled"),
	}

	// Load retryable errors
	if l.viper.IsSet(key + ".retryable_errors") {
		policy.RetryableErrors = l.viper.GetStringSlice(key + ".retryable_errors")
	}

	return &policy
}

// loadCircuitBreakerConfig loads circuit breaker configuration from viper.
func (l *ConfigLoader) loadCircuitBreakerConfig(key string) *CircuitBreakerConfig {
	if !l.viper.IsSet(key) {
		return nil
	}

	config := CircuitBreakerConfig{
		FailureThreshold: l.viper.GetInt(key + ".failure_threshold"),
		Timeout:          l.viper.GetDuration(key + ".timeout"),
		HalfOpenRequests: l.viper.GetInt(key + ".half_open_requests"),
	}

	return &config
}

// LoadConfigFromViper is a convenience function that loads retry configuration from viper.
func LoadConfigFromViper(v *viper.Viper) (Config, error) {
	loader := NewConfigLoader(v)
	return loader.LoadConfig()
}

// BindRetryConfig binds retry configuration keys to viper with environment variable support.
func BindRetryConfig(v *viper.Viper) {
	// Bind database retry configuration
	v.BindEnv("retry.database.enabled", "RETRY_DATABASE_ENABLED")                       //nolint:errcheck
	v.BindEnv("retry.database.max_attempts", "RETRY_DATABASE_MAX_ATTEMPTS")             //nolint:errcheck
	v.BindEnv("retry.database.initial_delay", "RETRY_DATABASE_INITIAL_DELAY")           //nolint:errcheck
	v.BindEnv("retry.database.max_delay", "RETRY_DATABASE_MAX_DELAY")                   //nolint:errcheck
	v.BindEnv("retry.database.backoff_multiplier", "RETRY_DATABASE_BACKOFF_MULTIPLIER") //nolint:errcheck
	v.BindEnv("retry.database.jitter_enabled", "RETRY_DATABASE_JITTER_ENABLED")         //nolint:errcheck

	// Bind external services retry configuration
	v.BindEnv("retry.external_services.enabled", "RETRY_EXTERNAL_SERVICES_ENABLED")                       //nolint:errcheck
	v.BindEnv("retry.external_services.max_attempts", "RETRY_EXTERNAL_SERVICES_MAX_ATTEMPTS")             //nolint:errcheck
	v.BindEnv("retry.external_services.initial_delay", "RETRY_EXTERNAL_SERVICES_INITIAL_DELAY")           //nolint:errcheck
	v.BindEnv("retry.external_services.max_delay", "RETRY_EXTERNAL_SERVICES_MAX_DELAY")                   //nolint:errcheck
	v.BindEnv("retry.external_services.backoff_multiplier", "RETRY_EXTERNAL_SERVICES_BACKOFF_MULTIPLIER") //nolint:errcheck
	v.BindEnv("retry.external_services.jitter_enabled", "RETRY_EXTERNAL_SERVICES_JITTER_ENABLED")         //nolint:errcheck

	// Bind service operations retry configuration
	v.BindEnv("retry.service_operations.enabled", "RETRY_SERVICE_OPERATIONS_ENABLED")                       //nolint:errcheck
	v.BindEnv("retry.service_operations.max_attempts", "RETRY_SERVICE_OPERATIONS_MAX_ATTEMPTS")             //nolint:errcheck
	v.BindEnv("retry.service_operations.initial_delay", "RETRY_SERVICE_OPERATIONS_INITIAL_DELAY")           //nolint:errcheck
	v.BindEnv("retry.service_operations.max_delay", "RETRY_SERVICE_OPERATIONS_MAX_DELAY")                   //nolint:errcheck
	v.BindEnv("retry.service_operations.backoff_multiplier", "RETRY_SERVICE_OPERATIONS_BACKOFF_MULTIPLIER") //nolint:errcheck
	v.BindEnv("retry.service_operations.jitter_enabled", "RETRY_SERVICE_OPERATIONS_JITTER_ENABLED")         //nolint:errcheck

	// Bind circuit breaker configuration
	v.BindEnv("retry.circuit_breaker.failure_threshold", "RETRY_CIRCUIT_BREAKER_FAILURE_THRESHOLD")   //nolint:errcheck
	v.BindEnv("retry.circuit_breaker.timeout", "RETRY_CIRCUIT_BREAKER_TIMEOUT")                       //nolint:errcheck
	v.BindEnv("retry.circuit_breaker.half_open_requests", "RETRY_CIRCUIT_BREAKER_HALF_OPEN_REQUESTS") //nolint:errcheck
}

// SetRetryDefaults sets default values for retry configuration.
func SetRetryDefaults(v *viper.Viper) {
	// Database retry defaults
	v.SetDefault("retry.database.enabled", true)
	v.SetDefault("retry.database.max_attempts", 3)
	v.SetDefault("retry.database.initial_delay", "100ms")
	v.SetDefault("retry.database.max_delay", "5s")
	v.SetDefault("retry.database.backoff_multiplier", 2.0)
	v.SetDefault("retry.database.jitter_enabled", true)
	v.SetDefault("retry.database.retryable_errors", []string{
		"connection refused",
		"database is locked",
		"busy",
		"timeout",
	})

	// External services retry defaults
	v.SetDefault("retry.external_services.enabled", true)
	v.SetDefault("retry.external_services.max_attempts", 5)
	v.SetDefault("retry.external_services.initial_delay", "1s")
	v.SetDefault("retry.external_services.max_delay", "30s")
	v.SetDefault("retry.external_services.backoff_multiplier", 2.0)
	v.SetDefault("retry.external_services.jitter_enabled", true)
	v.SetDefault("retry.external_services.retryable_errors", []string{
		"connection refused",
		"no such host",
		"timeout",
		"temporary failure",
		"service unavailable",
		"too many requests",
	})

	// Service operations retry defaults
	v.SetDefault("retry.service_operations.enabled", true)
	v.SetDefault("retry.service_operations.max_attempts", 2)
	v.SetDefault("retry.service_operations.initial_delay", "500ms")
	v.SetDefault("retry.service_operations.max_delay", "2s")
	v.SetDefault("retry.service_operations.backoff_multiplier", 1.5)
	v.SetDefault("retry.service_operations.jitter_enabled", true)
	v.SetDefault("retry.service_operations.retryable_errors", []string{
		"connection refused",
		"timeout",
		"temporary failure",
	})

	// Circuit breaker defaults
	v.SetDefault("retry.circuit_breaker.failure_threshold", 5)
	v.SetDefault("retry.circuit_breaker.timeout", "60s")
	v.SetDefault("retry.circuit_breaker.half_open_requests", 3)
}

// RetryConfigFromEnvironment creates a retry configuration based on environment.
func RetryConfigFromEnvironment(env string) Config {
	switch env {
	case "development":
		return DevelopmentConfig()
	case "test", "testing":
		return TestingConfig()
	case "production", "prod":
		return ProductionConfig()
	default:
		return DefaultConfig()
	}
}

// mergePolicyWithDefaults merges a policy with default values, preferring the provided policy values.
func mergePolicyWithDefaults(policy Policy, defaults Policy) Policy {
	result := defaults

	if policy.Enabled != result.Enabled {
		result.Enabled = policy.Enabled
	}
	// Only override MaxAttempts if it's explicitly set (even to 0)
	// We need to check if it was set in the config, not just if it's non-zero
	result.MaxAttempts = policy.MaxAttempts
	if policy.InitialDelay != 0 {
		result.InitialDelay = policy.InitialDelay
	}
	if policy.MaxDelay != 0 {
		result.MaxDelay = policy.MaxDelay
	}
	if policy.BackoffMultiplier != 0 {
		result.BackoffMultiplier = policy.BackoffMultiplier
	}
	if len(policy.RetryableErrors) > 0 {
		result.RetryableErrors = policy.RetryableErrors
	}
	if policy.JitterEnabled != result.JitterEnabled {
		result.JitterEnabled = policy.JitterEnabled
	}

	return result
}

// ConfigLoaderInterface defines the interface for loading retry configuration.
type ConfigLoaderInterface interface {
	LoadConfig() (Config, error)
}

// Ensure ConfigLoader implements ConfigLoaderInterface
var _ ConfigLoaderInterface = (*ConfigLoader)(nil)
