package cliclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"rocketvault/model"
)

// secretsBaseURL builds the secrets collection URL for server: vault-scoped
// ({server}/api/v1/vaults/{vault}/secrets) when vault is non-empty, or the
// legacy default-vault path ({server}/api/v1/secrets) otherwise. Mirrors the
// vault-flag semantics local mode uses.
func secretsBaseURL(server, vault string) string {
	if vault != "" {
		return server + "/api/v1/vaults/" + url.PathEscape(vault) + "/secrets"
	}
	return server + "/api/v1/secrets"
}

// secretsAPIError classifies a non-2xx secrets API response into a CLI-facing
// error, reading the standard {"message": ...} error body when present.
func secretsAPIError(op string, resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("cliclient: server rejected the session token (401) — it may be expired or revoked; re-run with --username/--password/--totp-code to re-authenticate")
	case http.StatusForbidden:
		return fmt.Errorf("cliclient: server denied access (403) — the authenticated principal has no role assignment granting the required data action on this vault")
	case http.StatusNotFound:
		return fmt.Errorf("cliclient: %s: secret not found (404)", op)
	}

	var body struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err == nil && body.Message != "" {
		return fmt.Errorf("cliclient: %s failed: %s (%s)", op, body.Message, resp.Status)
	}
	return fmt.Errorf("cliclient: %s failed: server returned %s", op, resp.Status)
}

// ListSecretsRemote calls GET {server}/api/v1/secrets (or the vault-scoped
// {server}/api/v1/vaults/{vault}/secrets when vault is non-empty) and
// returns the decoded secret list, exactly as the API returns it -- callers
// format it for display.
func ListSecretsRemote(ctx context.Context, httpClient *http.Client, token, server, vault string, tags []string) ([]model.SecretResponse, error) {
	target := secretsBaseURL(server, vault)
	if len(tags) > 0 {
		target += "?tags=" + url.QueryEscape(strings.Join(tags, ","))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("cliclient: build secrets list request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cliclient: secrets list request to %s: %w", server, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, secretsAPIError("secrets list", resp)
	}

	var lr model.ListSecretsResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return nil, fmt.Errorf("cliclient: decode secrets list response: %w", err)
	}
	return lr.Secrets, nil
}

// GetSecretRemote calls GET {secretsBaseURL}/{id} and returns the decoded
// secret, including its decrypted value.
func GetSecretRemote(ctx context.Context, httpClient *http.Client, token, server, vault, id string) (*model.SecretResponse, error) {
	target := secretsBaseURL(server, vault) + "/" + url.PathEscape(id)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("cliclient: build secret get request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cliclient: secret get request to %s: %w", server, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, secretsAPIError("secret get", resp)
	}

	var sr model.SecretResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, fmt.Errorf("cliclient: decode secret get response: %w", err)
	}
	return &sr, nil
}

// CreateSecretRemote calls POST {secretsBaseURL} with req as the JSON body
// and returns the decoded (valueless) secret response.
func CreateSecretRemote(ctx context.Context, httpClient *http.Client, token, server, vault string, secretReq model.CreateSecretRequest) (*model.SecretResponse, error) {
	body, err := json.Marshal(secretReq)
	if err != nil {
		return nil, fmt.Errorf("cliclient: encode secret create request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, secretsBaseURL(server, vault), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cliclient: build secret create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cliclient: secret create request to %s: %w", server, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusCreated {
		return nil, secretsAPIError("secret create", resp)
	}

	var sr model.SecretResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, fmt.Errorf("cliclient: decode secret create response: %w", err)
	}
	return &sr, nil
}

// UpdateSecretRemote calls PUT {secretsBaseURL}/{id} with req as the JSON
// body and returns the decoded (valueless) secret response.
func UpdateSecretRemote(ctx context.Context, httpClient *http.Client, token, server, vault, id string, secretReq model.UpdateSecretRequest) (*model.SecretResponse, error) {
	body, err := json.Marshal(secretReq)
	if err != nil {
		return nil, fmt.Errorf("cliclient: encode secret update request: %w", err)
	}

	target := secretsBaseURL(server, vault) + "/" + url.PathEscape(id)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cliclient: build secret update request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cliclient: secret update request to %s: %w", server, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, secretsAPIError("secret update", resp)
	}

	var sr model.SecretResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, fmt.Errorf("cliclient: decode secret update response: %w", err)
	}
	return &sr, nil
}

// DeleteSecretRemote calls DELETE {secretsBaseURL}/{id}.
func DeleteSecretRemote(ctx context.Context, httpClient *http.Client, token, server, vault, id string) error {
	target := secretsBaseURL(server, vault) + "/" + url.PathEscape(id)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, target, nil)
	if err != nil {
		return fmt.Errorf("cliclient: build secret delete request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("cliclient: secret delete request to %s: %w", server, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return secretsAPIError("secret delete", resp)
	}
	return nil
}

// ExportSecretsRemote calls POST {secretsBaseURL}/export with exportReq as
// the JSON body and returns the raw exported file bytes -- the server
// streams a file (Content-Disposition attachment), not a JSON envelope, so
// the caller writes the returned bytes straight to disk exactly as
// "secrets export" always has.
func ExportSecretsRemote(ctx context.Context, httpClient *http.Client, token, server, vault string, exportReq model.ExportSecretsRequest) ([]byte, error) {
	body, err := json.Marshal(exportReq)
	if err != nil {
		return nil, fmt.Errorf("cliclient: encode secrets export request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, secretsBaseURL(server, vault)+"/export", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cliclient: build secrets export request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cliclient: secrets export request to %s: %w", server, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, secretsAPIError("secrets export", resp)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cliclient: read secrets export response: %w", err)
	}
	return data, nil
}

// ImportSecretsRemote calls POST {secretsBaseURL}/import as a multipart form
// (file + format + overwrite + optional passphrase), matching what the
// server's importSecrets handler expects -- the server detects and decrypts
// a sealed export itself when passphrase is non-empty, exactly as local
// mode's own encrypted-file handling does, so no client-side decryption is
// needed here.
func ImportSecretsRemote(ctx context.Context, httpClient *http.Client, token, server, vault string, fileData []byte, format string, overwrite bool, passphrase string) (*model.ImportResponse, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	part, err := w.CreateFormFile("file", "import")
	if err != nil {
		return nil, fmt.Errorf("cliclient: build import multipart body: %w", err)
	}
	if _, err := part.Write(fileData); err != nil {
		return nil, fmt.Errorf("cliclient: write import file part: %w", err)
	}
	_ = w.WriteField("format", format)
	_ = w.WriteField("overwrite", strconv.FormatBool(overwrite))
	if passphrase != "" {
		_ = w.WriteField("passphrase", passphrase)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("cliclient: finalize import multipart body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, secretsBaseURL(server, vault)+"/import", &buf)
	if err != nil {
		return nil, fmt.Errorf("cliclient: build secrets import request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cliclient: secrets import request to %s: %w", server, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, secretsAPIError("secrets import", resp)
	}

	var ir model.ImportResponse
	if err := json.NewDecoder(resp.Body).Decode(&ir); err != nil {
		return nil, fmt.Errorf("cliclient: decode secrets import response: %w", err)
	}
	return &ir, nil
}
