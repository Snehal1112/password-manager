package main

import (
	"fmt"
	"os"

	"github.com/spf13/viper"

	"rocketvault/internal/vaultclient"
)

// AppConfig holds all configuration for the consumer service.
type AppConfig struct {
	VaultURL     string
	ClientID     string
	ClientSecret string
	Vault        string
	Secrets      []vaultclient.SecretMapping
	Listen       string
}

// loadConfig reads config.yaml from the examples/consumer-service directory,
// then applies VAULT_URL, VAULT_CLIENT_ID, VAULT_CLIENT_SECRET env var overrides.
func loadConfig() (*AppConfig, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./examples/consumer-service")
	v.AddConfigPath(".")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("loadConfig: %w", err)
	}

	// Env vars override config file values.
	url := v.GetString("vault.url")
	if env := os.Getenv("VAULT_URL"); env != "" {
		url = env
	}

	clientID := v.GetString("vault.client_id")
	if env := os.Getenv("VAULT_CLIENT_ID"); env != "" {
		clientID = env
	}

	// client_secret is env-only — never stored in config file.
	clientSecret := os.Getenv("VAULT_CLIENT_SECRET")

	// vault_name is optional — empty targets the server's `default` vault.
	vault := v.GetString("vault.vault_name")
	if env := os.Getenv("VAULT_NAME"); env != "" {
		vault = env
	}

	var secrets []vaultclient.SecretMapping
	if err := v.UnmarshalKey("vault.secrets", &secrets); err != nil {
		return nil, fmt.Errorf("loadConfig: vault.secrets: %w", err)
	}

	listen := v.GetString("server.listen")
	if listen == "" {
		listen = ":9000"
	}

	return &AppConfig{
		VaultURL:     url,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Vault:        vault,
		Secrets:      secrets,
		Listen:       listen,
	}, nil
}
