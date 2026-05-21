package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"rocketvault/internal/vaultclient"
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	// Build vault client — fatal if credentials are missing or auth fails.
	client, err := vaultclient.New(vaultclient.Config{
		URL:          cfg.VaultURL,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "vault client: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	// Fetch each secret individually — non-fatal on 404/network error, fatal on auth failure.
	secretStatuses := make(map[string]SecretStatus, len(cfg.Secrets))
	for _, s := range cfg.Secrets {
		if s.UUID == "" {
			secretStatuses[s.Name] = SecretStatus{
				Loaded: false,
				Error:  "uuid not configured",
			}
			continue
		}

		val, fetchErr := client.Get(ctx, s.UUID)
		if fetchErr != nil {
			if errors.Is(fetchErr, vaultclient.ErrAuthFailed) {
				fmt.Fprintf(os.Stderr, "vault auth failed: %v\n", fetchErr)
				os.Exit(1)
			}
			secretStatuses[s.Name] = SecretStatus{
				Loaded: false,
				Error:  fetchErr.Error(),
			}
			continue
		}

		secretStatuses[s.Name] = SecretStatus{
			Loaded: true,
			Masked: maskSecret(val),
		}
	}

	// Fetch frontend config from RocketVault — non-fatal.
	frontendCfg, frontendErr := fetchFrontendConfig(cfg.VaultURL)

	status := StatusResponse{
		VaultURL:       cfg.VaultURL,
		ClientID:       cfg.ClientID,
		Secrets:        secretStatuses,
		FrontendConfig: frontendCfg,
	}
	if frontendErr != nil {
		status.FrontendConfigError = frontendErr.Error()
	}

	srv := NewServer(status, cfg.Listen)
	fmt.Printf("consumer service listening on %s\n", cfg.Listen)
	fmt.Printf("  vault: %s (client_id: %s)\n", cfg.VaultURL, cfg.ClientID)
	fmt.Printf("  GET %s/status  — secret load results\n", cfg.Listen)
	fmt.Printf("  GET %s/healthz — liveness check\n", cfg.Listen)

	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

// fetchFrontendConfig calls GET /api/v1/config on RocketVault.
func fetchFrontendConfig(vaultURL string) (map[string]any, error) {
	resp, err := http.Get(vaultURL + "/api/v1/config") //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("GET /api/v1/config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /api/v1/config: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GET /api/v1/config: read body: %w", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("GET /api/v1/config: decode: %w", err)
	}
	return result, nil
}
