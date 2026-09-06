package config

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"rocketvault/internal/cachekit"
	"rocketvault/internal/logging"

	"github.com/spf13/viper"
)

// SoftDeleteConfig controls soft-delete and purge protection behaviour.
type SoftDeleteConfig struct {
	Enabled         bool `mapstructure:"enabled"`
	RetentionDays   int  `mapstructure:"retention_days"`
	PurgeProtection bool `mapstructure:"purge_protection"`
}

// LoadSoftDeleteConfig reads soft-delete settings from Viper.
// Falls back to safe defaults if keys are not set.
func LoadSoftDeleteConfig() SoftDeleteConfig {
	cfg := SoftDeleteConfig{
		Enabled:         true,
		RetentionDays:   30,
		PurgeProtection: false,
	}
	if viper.IsSet("soft_delete.enabled") {
		cfg.Enabled = viper.GetBool("soft_delete.enabled")
	}
	if viper.IsSet("soft_delete.retention_days") {
		cfg.RetentionDays = viper.GetInt("soft_delete.retention_days")
	}
	if viper.IsSet("soft_delete.purge_protection") {
		cfg.PurgeProtection = viper.GetBool("soft_delete.purge_protection")
	}
	return cfg
}

// MonitoringConfig controls Prometheus metrics exposure and slow-query detection.
type MonitoringConfig struct {
	EnableMetrics      bool          `mapstructure:"enable_metrics"`
	MetricsInterval    time.Duration `mapstructure:"metrics_interval"`
	SlowQueryThreshold time.Duration `mapstructure:"slow_query_threshold"`
}

// LoadMonitoringConfig reads monitoring settings from Viper.
// Falls back to safe defaults if keys are not set.
func LoadMonitoringConfig() MonitoringConfig {
	cfg := MonitoringConfig{
		EnableMetrics:      true,
		MetricsInterval:    60 * time.Second,
		SlowQueryThreshold: 100 * time.Millisecond,
	}
	if viper.IsSet("monitoring.enable_metrics") {
		cfg.EnableMetrics = viper.GetBool("monitoring.enable_metrics")
	}
	if viper.IsSet("monitoring.metrics_interval") {
		cfg.MetricsInterval = viper.GetDuration("monitoring.metrics_interval")
	}
	if viper.IsSet("monitoring.slow_query_threshold") {
		cfg.SlowQueryThreshold = viper.GetDuration("monitoring.slow_query_threshold")
	}
	return cfg
}

// ResourceRotationConfig controls one resource type's rotation scheduler.
type ResourceRotationConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	Interval time.Duration `mapstructure:"interval"`
}

// RotationConfig holds ResourceRotationConfig for every resource type with a
// rotation scheduler: secrets, certificates, and keys.
type RotationConfig struct {
	Secrets      ResourceRotationConfig `mapstructure:"secrets"`
	Certificates ResourceRotationConfig `mapstructure:"certificates"`
	Keys         ResourceRotationConfig `mapstructure:"keys"`
}

// loadResourceRotationConfig reads one resource type's rotation.<prefix>.*
// keys from Viper, overriding def field-by-field for whichever keys are
// explicitly set.
func loadResourceRotationConfig(prefix string, def ResourceRotationConfig) ResourceRotationConfig {
	cfg := def
	if viper.IsSet(prefix + ".enabled") {
		cfg.Enabled = viper.GetBool(prefix + ".enabled")
	}
	if viper.IsSet(prefix + ".interval") {
		cfg.Interval = viper.GetDuration(prefix + ".interval")
	}
	return cfg
}

// LoadRotationConfig reads rotation.<resource>.* settings from Viper for
// secrets, certificates, and keys, falling back to defaults that exactly
// match this codebase's previous hardcoded values (1h for secrets and keys,
// 24h for certificates) so a config with no rotation: section behaves
// identically to before this config section existed.
func LoadRotationConfig() RotationConfig {
	return RotationConfig{
		Secrets:      loadResourceRotationConfig("rotation.secrets", ResourceRotationConfig{Enabled: true, Interval: time.Hour}),
		Certificates: loadResourceRotationConfig("rotation.certificates", ResourceRotationConfig{Enabled: true, Interval: 24 * time.Hour}),
		Keys:         loadResourceRotationConfig("rotation.keys", ResourceRotationConfig{Enabled: true, Interval: time.Hour}),
	}
}

// CacheConfig holds cachekit.Config for every domain that caches records.
type CacheConfig struct {
	Secrets      cachekit.Config
	Keys         cachekit.Config
	Vaults       cachekit.Config
	Certificates cachekit.Config
	Users        cachekit.Config
}

// loadCacheDomainConfig reads one domain's cache.<prefix>.* keys from Viper,
// overriding def field-by-field for whichever keys are explicitly set.
func loadCacheDomainConfig(prefix string, def cachekit.Config) cachekit.Config {
	cfg := def
	if viper.IsSet(prefix + ".enabled") {
		cfg.Enabled = viper.GetBool(prefix + ".enabled")
	}
	if viper.IsSet(prefix + ".ttl") {
		cfg.TTL = viper.GetDuration(prefix + ".ttl")
	}
	if viper.IsSet(prefix + ".cleanup_interval") {
		cfg.CleanupInterval = viper.GetDuration(prefix + ".cleanup_interval")
	}
	if viper.IsSet(prefix + ".max_entries") {
		cfg.MaxEntries = viper.GetInt(prefix + ".max_entries")
	}
	return cfg
}

// LoadCacheConfig reads cache.<domain>.* settings from Viper for all five
// domains, falling back to safe per-domain defaults, and validates each one.
// users defaults Enabled: false — no cache wrapper consumes it yet (see
// docs/superpowers/specs/2026-08-14-generic-cache-config-design.md).
// Certificates defaults Enabled: true as of internal/certcache's
// CachedCertificateService, mirroring Secrets/Keys/Vaults.
func LoadCacheConfig() (CacheConfig, error) {
	cfg := CacheConfig{
		Secrets:      loadCacheDomainConfig("cache.secrets", cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 1000}),
		Keys:         loadCacheDomainConfig("cache.keys", cachekit.Config{Enabled: true, TTL: 60 * time.Second, CleanupInterval: 30 * time.Second, MaxEntries: 500}),
		Vaults:       loadCacheDomainConfig("cache.vaults", cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 500}),
		Certificates: loadCacheDomainConfig("cache.certificates", cachekit.Config{Enabled: true, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 500}),
		Users:        loadCacheDomainConfig("cache.users", cachekit.Config{Enabled: false, TTL: 5 * time.Minute, CleanupInterval: time.Minute, MaxEntries: 500}),
	}

	domains := []struct {
		name string
		cfg  cachekit.Config
	}{
		{"secrets", cfg.Secrets}, {"keys", cfg.Keys}, {"vaults", cfg.Vaults},
		{"certificates", cfg.Certificates}, {"users", cfg.Users},
	}
	for _, d := range domains {
		if err := d.cfg.Validate(); err != nil {
			return CacheConfig{}, fmt.Errorf("cache.%s: %w", d.name, err)
		}
	}
	return cfg, nil
}

// Config holds the configuration settings for the vault service application.
// It includes settings for the server's listening address, logging, HTTP transport,
// and trusted proxy IPs and networks.
type Config struct {
	// ListenAddr is the address on which the server will listen for incoming requests.
	ListenAddr string

	// Logger is the logger used for logging messages.
	Logger *logging.Logger

	// HTTPTransport is the transport used for making HTTP requests.
	HTTPTransport http.RoundTripper

	// TrustedProxyIPs is a list of IP addresses that are considered trusted proxies.
	TrustedProxyIPs []*net.IP

	// TrustedProxyNets is a list of IP networks that are considered trusted proxies.
	TrustedProxyNets []*net.IPNet

	// SoftDelete holds soft-delete and purge protection settings.
	SoftDelete SoftDeleteConfig `mapstructure:"soft_delete"`
}

// MCPMaxResultsCeiling bounds mcp.max_results.
//
// An unbounded list tool would pour thousands of rows straight into a model's
// context, so the ceiling is a hard limit rather than a suggestion.
const MCPMaxResultsCeiling = 200

// mcpClientSecretEnv is the environment variable holding the service-account
// secret, which takes precedence over the YAML key so a deployment need not
// write it to disk. This constant is a variable name, never a secret value.
const mcpClientSecretEnv = "ROCKETVAULT_MCP_CLIENT_SECRET" //nolint:gosec // env var name, not a credential

// MCPRateLimit bounds how fast tools may be called, per tool class.
type MCPRateLimit struct {
	ReadsPerMinute  int `mapstructure:"reads_per_minute"`
	WritesPerMinute int `mapstructure:"writes_per_minute"`
}

// MCPConfig governs the MCP server's capability surface.
//
// Every capability flag defaults to false: a config file with no mcp section
// must yield the most restrictive server possible. These flags only ever
// narrow what the authenticated principal's RBAC already permits — they
// cannot widen it, because the server enforces authorization independently.
type MCPConfig struct {
	// Vault is the default vault for tools that do not name one.
	Vault string `mapstructure:"vault"`
	// AllowedVaults pins the server to a set of vaults. Empty means any
	// vault the principal can reach.
	AllowedVaults []string `mapstructure:"allowed_vaults"`

	AllowWrite        bool `mapstructure:"allow_write"`
	AllowDestructive  bool `mapstructure:"allow_destructive"`
	AllowCrypto       bool `mapstructure:"allow_crypto"`
	AllowSecretValues bool `mapstructure:"allow_secret_values"`
	// AllowInteractiveLogin gates the login tool, which lets a chat message
	// re-authenticate this server's identity at runtime. It is meaningless
	// (and never registered, see mcpserver.TierLogin) under a service
	// account -- a service account's whole point is that the agent cannot
	// act as a human.
	AllowInteractiveLogin bool `mapstructure:"allow_interactive_login"`

	// RequireServiceAccount refuses the cached-session identity, so the agent
	// cannot act as the logged-in human. Production should set it.
	RequireServiceAccount bool `mapstructure:"require_service_account"`
	// ConfirmDestructive requires destructive tools to echo the exact
	// resource name. It defaults to true, the safer value.
	ConfirmDestructive bool `mapstructure:"confirm_destructive"`

	MaxResults     int           `mapstructure:"max_results"`
	RequestTimeout time.Duration `mapstructure:"request_timeout"`
	RateLimit      MCPRateLimit  `mapstructure:"rate_limit"`

	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
}

// UsesServiceAccount reports whether this configuration identifies a service
// account rather than relying on the cached CLI session. It is the single
// definition of that predicate, which gates both the identity the MCP server
// starts as and whether the login tool can ever be registered.
func (c MCPConfig) UsesServiceAccount() bool {
	return c.ClientID != "" && c.ClientSecret != ""
}

// LoadMCPConfig reads MCP settings from Viper, seeding restrictive defaults
// and overriding only keys that are actually set.
func LoadMCPConfig() (MCPConfig, error) {
	cfg := MCPConfig{
		Vault:              "default",
		ConfirmDestructive: true,
		MaxResults:         50,
		RequestTimeout:     30 * time.Second,
		RateLimit:          MCPRateLimit{ReadsPerMinute: 120, WritesPerMinute: 20},
	}

	if viper.IsSet("mcp.vault") {
		cfg.Vault = viper.GetString("mcp.vault")
	}
	if viper.IsSet("mcp.allowed_vaults") {
		cfg.AllowedVaults = viper.GetStringSlice("mcp.allowed_vaults")
	}
	if viper.IsSet("mcp.allow_write") {
		cfg.AllowWrite = viper.GetBool("mcp.allow_write")
	}
	if viper.IsSet("mcp.allow_destructive") {
		cfg.AllowDestructive = viper.GetBool("mcp.allow_destructive")
	}
	if viper.IsSet("mcp.allow_crypto") {
		cfg.AllowCrypto = viper.GetBool("mcp.allow_crypto")
	}
	if viper.IsSet("mcp.allow_secret_values") {
		cfg.AllowSecretValues = viper.GetBool("mcp.allow_secret_values")
	}
	if viper.IsSet("mcp.allow_interactive_login") {
		cfg.AllowInteractiveLogin = viper.GetBool("mcp.allow_interactive_login")
	}
	if viper.IsSet("mcp.require_service_account") {
		cfg.RequireServiceAccount = viper.GetBool("mcp.require_service_account")
	}
	if viper.IsSet("mcp.confirm_destructive") {
		cfg.ConfirmDestructive = viper.GetBool("mcp.confirm_destructive")
	}
	if viper.IsSet("mcp.max_results") {
		cfg.MaxResults = viper.GetInt("mcp.max_results")
	}
	if viper.IsSet("mcp.request_timeout") {
		cfg.RequestTimeout = viper.GetDuration("mcp.request_timeout")
	}
	if viper.IsSet("mcp.rate_limit.reads_per_minute") {
		cfg.RateLimit.ReadsPerMinute = viper.GetInt("mcp.rate_limit.reads_per_minute")
	}
	if viper.IsSet("mcp.rate_limit.writes_per_minute") {
		cfg.RateLimit.WritesPerMinute = viper.GetInt("mcp.rate_limit.writes_per_minute")
	}
	if viper.IsSet("mcp.client_id") {
		cfg.ClientID = viper.GetString("mcp.client_id")
	}
	if viper.IsSet("mcp.client_secret") {
		cfg.ClientSecret = viper.GetString("mcp.client_secret")
	}

	// The environment wins, so a deployment need not write the secret to disk.
	if fromEnv := os.Getenv(mcpClientSecretEnv); fromEnv != "" {
		cfg.ClientSecret = fromEnv
	}

	if err := cfg.Validate(); err != nil {
		return MCPConfig{}, err
	}
	return cfg, nil
}

// Validate reports whether the configuration is coherent.
//
// It rejects rather than clamps. A max_results of 5000 is not a value to
// quietly reduce: it means the operator believes something about this server
// that is not true, and a server that silently behaves differently from its
// config is worse than one that refuses to start.
//
// No error message includes the client secret.
func (c MCPConfig) Validate() error {
	if c.Vault == "" {
		return fmt.Errorf("mcp.vault must not be empty")
	}
	if c.MaxResults <= 0 {
		return fmt.Errorf("mcp.max_results must be positive, got %d", c.MaxResults)
	}
	if c.MaxResults > MCPMaxResultsCeiling {
		return fmt.Errorf("mcp.max_results must not exceed %d, got %d", MCPMaxResultsCeiling, c.MaxResults)
	}
	if c.RequestTimeout <= 0 {
		return fmt.Errorf("mcp.request_timeout must be positive, got %s", c.RequestTimeout)
	}
	if c.RateLimit.ReadsPerMinute <= 0 {
		return fmt.Errorf("mcp.rate_limit.reads_per_minute must be positive, got %d", c.RateLimit.ReadsPerMinute)
	}
	if c.RateLimit.WritesPerMinute <= 0 {
		return fmt.Errorf("mcp.rate_limit.writes_per_minute must be positive, got %d", c.RateLimit.WritesPerMinute)
	}

	for i, name := range c.AllowedVaults {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("mcp.allowed_vaults[%d] must not be blank", i)
		}
	}
	// A default vault the server is not allowed to touch would fail on every
	// call that does not name one explicitly.
	if len(c.AllowedVaults) > 0 && !containsString(c.AllowedVaults, c.Vault) {
		return fmt.Errorf("mcp.vault %q is not in mcp.allowed_vaults %v", c.Vault, c.AllowedVaults)
	}

	// Credentials are all-or-nothing: half a credential can only fail later,
	// at the first request, with a much less clear message.
	switch {
	case c.ClientID != "" && c.ClientSecret == "":
		return fmt.Errorf("mcp.client_id is set but mcp.client_secret is not; set it or %s", mcpClientSecretEnv)
	case c.ClientSecret != "" && c.ClientID == "":
		return fmt.Errorf("mcp.client_secret is set but mcp.client_id is not")
	}
	if c.RequireServiceAccount && c.ClientID == "" {
		return fmt.Errorf("mcp.require_service_account is true but no mcp.client_id is configured")
	}
	return nil
}

// containsString reports whether values contains target.
func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// RocketMemConfig holds connection settings for the optional shared
// Rocket-mem L2 cache tier (see internal/rocketmemcache and
// internal/cachekit.TieredCache). Disabled by default -- a deployment with
// no cache.rocket_mem section behaves identically to before this existed.
type RocketMemConfig struct {
	Enabled bool
	Addr    string
	TLS     bool
	// CAPath is optional: a PEM file to trust rocket-mem's TLS cert against,
	// for a self-signed or private-CA deployment. Empty verifies against the
	// system trust store instead.
	CAPath       string
	Username     string
	Password     string
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	PoolSize     int
	// ReconnectSteadyStateInterval is how often the background reconnect
	// supervisor polls Rocket-mem while it believes the connection is
	// healthy. <= 0 disables the supervisor entirely.
	ReconnectSteadyStateInterval time.Duration
	// ReconnectInitialBackoff is the first retry delay once a poll fails.
	ReconnectInitialBackoff time.Duration
	// ReconnectMaxBackoff caps the growing retry delay during a sustained
	// outage.
	ReconnectMaxBackoff time.Duration
	// ReconnectBackoffMultiplier grows the retry delay after each failed
	// poll (delay *= multiplier, capped at ReconnectMaxBackoff).
	ReconnectBackoffMultiplier float64
}

// LoadRocketMemConfig reads cache.rocket_mem.* from Viper. Fails closed:
// Rocket-mem defaults to a fully open ACL until at least one user is
// configured (verified against its source), so enabling this cache without
// both TLS and credentials would hand a network-adjacent attacker
// cache-poisoning/DoS capability even though cached payloads are
// encrypted. Mirrors this codebase's existing pattern of aborting startup
// on a bad security-relevant config (e.g. master_key) rather than
// degrading silently.
func LoadRocketMemConfig() (RocketMemConfig, error) {
	cfg := RocketMemConfig{
		Addr:                         "127.0.0.1:6379",
		DialTimeout:                  100 * time.Millisecond,
		ReadTimeout:                  100 * time.Millisecond,
		WriteTimeout:                 100 * time.Millisecond,
		PoolSize:                     10,
		ReconnectSteadyStateInterval: 30 * time.Second,
		ReconnectInitialBackoff:      1 * time.Second,
		ReconnectMaxBackoff:          60 * time.Second,
		ReconnectBackoffMultiplier:   2.0,
	}
	if viper.IsSet("cache.rocket_mem.enabled") {
		cfg.Enabled = viper.GetBool("cache.rocket_mem.enabled")
	}
	if viper.IsSet("cache.rocket_mem.addr") {
		cfg.Addr = viper.GetString("cache.rocket_mem.addr")
	}
	if viper.IsSet("cache.rocket_mem.tls") {
		cfg.TLS = viper.GetBool("cache.rocket_mem.tls")
	}
	if viper.IsSet("cache.rocket_mem.ca_path") {
		cfg.CAPath = viper.GetString("cache.rocket_mem.ca_path")
	}
	if viper.IsSet("cache.rocket_mem.username") {
		cfg.Username = viper.GetString("cache.rocket_mem.username")
	}
	if viper.IsSet("cache.rocket_mem.password") {
		cfg.Password = viper.GetString("cache.rocket_mem.password")
	}
	if viper.IsSet("cache.rocket_mem.dial_timeout") {
		cfg.DialTimeout = viper.GetDuration("cache.rocket_mem.dial_timeout")
	}
	if viper.IsSet("cache.rocket_mem.read_timeout") {
		cfg.ReadTimeout = viper.GetDuration("cache.rocket_mem.read_timeout")
	}
	if viper.IsSet("cache.rocket_mem.write_timeout") {
		cfg.WriteTimeout = viper.GetDuration("cache.rocket_mem.write_timeout")
	}
	if viper.IsSet("cache.rocket_mem.pool_size") {
		cfg.PoolSize = viper.GetInt("cache.rocket_mem.pool_size")
	}
	if viper.IsSet("cache.rocket_mem.reconnect_steady_state_interval") {
		cfg.ReconnectSteadyStateInterval = viper.GetDuration("cache.rocket_mem.reconnect_steady_state_interval")
	}
	if viper.IsSet("cache.rocket_mem.reconnect_initial_backoff") {
		cfg.ReconnectInitialBackoff = viper.GetDuration("cache.rocket_mem.reconnect_initial_backoff")
	}
	if viper.IsSet("cache.rocket_mem.reconnect_max_backoff") {
		cfg.ReconnectMaxBackoff = viper.GetDuration("cache.rocket_mem.reconnect_max_backoff")
	}
	if viper.IsSet("cache.rocket_mem.reconnect_backoff_multiplier") {
		cfg.ReconnectBackoffMultiplier = viper.GetFloat64("cache.rocket_mem.reconnect_backoff_multiplier")
	}

	if cfg.Enabled && (!cfg.TLS || cfg.Username == "" || cfg.Password == "") {
		return RocketMemConfig{}, fmt.Errorf(
			"cache.rocket_mem: enabled requires tls=true and a non-empty username/password " +
				"(rocket-mem defaults to a fully open ACL until a user is configured)")
	}
	return cfg, nil
}
