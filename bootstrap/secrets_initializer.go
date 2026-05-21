package bootstrap

import (
	"context"
	"fmt"

	"github.com/spf13/viper"

	"rocketvault/internal/vaultclient"
)

// SecretsInitializer fetches secrets from RocketVault at startup and injects them
// into Viper so the service container can read them normally.
// It follows the same initializer pattern as DatabaseInitializer and ConfigurationValidator.
type SecretsInitializer struct {
	client  vaultclient.Fetcher
	mapping map[string]string // vaultName -> viperKey
}

// NewSecretsInitializer creates a SecretsInitializer.
// mapping maps vault secret names (from vault_client.secrets) to Viper config keys.
// Example: map[string]string{"JWT_SECRET": "jwt_secret", "DB_PASSWORD": "database.password"}
func NewSecretsInitializer(client vaultclient.Fetcher, mapping map[string]string) *SecretsInitializer {
	return &SecretsInitializer{client: client, mapping: mapping}
}

// NewSecretsInitializerFromMappings builds a SecretsInitializer from the
// vault_client.secrets config entries, using each entry's ViperKey as the
// injection target.
func NewSecretsInitializerFromMappings(client vaultclient.Fetcher, mappings []vaultclient.SecretMapping) *SecretsInitializer {
	m := make(map[string]string, len(mappings))
	for _, s := range mappings {
		if s.ViperKey != "" {
			m[s.Name] = s.ViperKey
		}
	}
	return NewSecretsInitializer(client, m)
}

// Initialize fetches the configured secrets and injects them into Viper.
// Never logs secret values — only names.
func (s *SecretsInitializer) Initialize(ctx context.Context) error {
	names := make([]string, 0, len(s.mapping))
	for name := range s.mapping {
		names = append(names, name)
	}

	secrets, err := s.client.GetMany(ctx, names)
	if err != nil {
		return fmt.Errorf("secrets initializer: %w", err)
	}

	for vaultName, viperKey := range s.mapping {
		if val, ok := secrets[vaultName]; ok {
			viper.Set(viperKey, val)
		}
	}
	return nil
}
