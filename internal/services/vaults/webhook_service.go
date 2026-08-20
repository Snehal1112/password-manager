package vaults

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// ErrWebhookNotFound is returned when a vault has no webhook config.
var ErrWebhookNotFound = errors.New("webhook config not found")

// ErrInvalidWebhookURL is returned when the supplied URL is not an absolute
// https URL with a host, or when it embeds credentials.
//
// Validation stays minimal by design: SSRF policy (private-range blocking,
// allowlists, redirect handling) belongs to the sub-project that actually
// makes the outbound call, not to a layer that never dials anything. The
// credential check is the deliberate exception, because it is a storage
// concern rather than a request-time one -- this layer is what writes the URL
// to a column it does not encrypt.
var ErrInvalidWebhookURL = errors.New("webhook url must be an absolute https URL")

// webhookSecretBytes is the entropy of a generated signing secret, before
// base64 encoding.
const webhookSecretBytes = 32

// UpsertWebhookRequest is the service-layer input for creating or updating a
// vault's webhook config.
//
// There is no client-supplied secret: the server mints it. RotateSecret
// replaces an existing secret; Enabled is a pointer so nil means "keep the
// current value" rather than "set false".
type UpsertWebhookRequest struct {
	URL          string
	RotateSecret bool
	Enabled      *bool
}

// VaultWebhookService manages per-vault webhook configuration.
//
// It performs no authorization. Callers authorize with
// authorization.CanManageVault before invoking it -- the API handlers and the
// CLI -- which is the same edge-authorized split VaultService and
// VaultRepository already use.
type VaultWebhookService interface {
	// Upsert creates or updates the vault's config. plaintextSecret is
	// non-empty only when this call minted a secret: always on create, and on
	// update only when req.RotateSecret is true. That empty/non-empty
	// distinction is how the caller knows whether to show the secret.
	//
	// actor is the principal performing the change, recorded in the audit
	// trail. It is NOT used for authorization -- callers authorize with
	// CanManageVault at the edge before calling. Passing uuid.Nil produces a
	// record attributed to nobody, which defeats the point of the trail.
	Upsert(ctx context.Context, vaultID uuid.UUID, req UpsertWebhookRequest, actor uuid.UUID) (cfg *model.VaultWebhookConfig, plaintextSecret string, err error)
	// Get returns the vault's config, or ErrWebhookNotFound. The returned
	// config carries the encrypted secret, never the plaintext. There is no
	// actor parameter: reads are not audited, matching GetVault.
	Get(ctx context.Context, vaultID uuid.UUID) (*model.VaultWebhookConfig, error)
	// Delete removes the vault's config. Deleting when none exists succeeds.
	// actor is recorded in the audit trail, as for Upsert.
	Delete(ctx context.Context, vaultID uuid.UUID, actor uuid.UUID) error
}

type vaultWebhookService struct {
	repo repositories.VaultWebhookRepositoryInterface
	log  *logging.Logger
}

// NewVaultWebhookService constructs a VaultWebhookService over the given repository.
func NewVaultWebhookService(repo repositories.VaultWebhookRepositoryInterface, log *logging.Logger) VaultWebhookService {
	return &vaultWebhookService{repo: repo, log: log}
}

// validateWebhookURL enforces an absolute https URL with a host and no
// embedded credentials.
//
// No error returned here may quote the supplied URL. This error text travels
// verbatim to the caller -- api/vault_webhook.go turns it into a 400 body via
// SetInvalidParam, and the CLI prints it -- so echoing the input would hand a
// credential back to whoever sent it, and into anything logging that response.
// That is why the parse failure below reports a fixed reason instead of
// wrapping url.Parse's own error, whose text embeds the full raw input.
func validateWebhookURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		// Deliberately does not wrap err: its message quotes raw in full.
		return fmt.Errorf("%w: could not be parsed as a URL", ErrInvalidWebhookURL)
	}
	if parsed.Scheme != "https" {
		// Safe to quote: a scheme cannot carry userinfo.
		return fmt.Errorf("%w: got scheme %q", ErrInvalidWebhookURL, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: missing host", ErrInvalidWebhookURL)
	}
	// Reject any userinfo, with or without a password, and even when empty.
	// vault_webhook_configs.url is the one column on this table stored
	// unencrypted, and GET returns it verbatim, so a credential embedded here
	// would sit in cleartext in the database, in every read, and in backups.
	// Stripping it silently instead would change what the operator asked for
	// and surface later as an unexplained authentication failure at the
	// receiver; refusing at configuration time is the honest failure.
	if parsed.User != nil {
		return fmt.Errorf("%w: must not embed credentials (user:password@); "+
			"authenticate the receiver with this vault's webhook signing secret instead", ErrInvalidWebhookURL)
	}
	return nil
}

// mintSecret returns a new base64-encoded signing secret: 32 random bytes
// encoded with base64.RawURLEncoding, a 43-character unpadded string.
//
// That returned string, in full, IS the secret -- not the 32 bytes it
// decodes to. It is what the operator copies out of the create/rotate
// response (the only place it is ever shown), so it is what a receiver will
// hold and use directly as HMAC key material. Any future delivery/signing
// implementation must HMAC with the 43-character string's bytes as received,
// not with base64.RawURLEncoding.DecodeString(secret) -- decoding first would
// silently produce a different key than what the operator configured on the
// receiving end.
func mintSecret() (string, error) {
	buf := make([]byte, webhookSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate webhook signing secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Upsert creates or updates the vault's webhook config.
func (s *vaultWebhookService) Upsert(ctx context.Context, vaultID uuid.UUID, req UpsertWebhookRequest, actor uuid.UUID) (*model.VaultWebhookConfig, string, error) {
	// 1. Validate before touching storage.
	if err := validateWebhookURL(req.URL); err != nil {
		return nil, "", err
	}

	// 2. Learn whether this is a create, and recover the current ciphertext.
	existing, err := s.repo.GetByVaultID(ctx, vaultID)
	if err != nil && !errors.Is(err, repositories.ErrNotFound) {
		return nil, "", fmt.Errorf("read existing webhook config: %w", err)
	}
	creating := existing == nil

	now := time.Now().UTC()
	cfg := &model.VaultWebhookConfig{
		VaultID:   vaultID,
		URL:       req.URL,
		UpdatedAt: now,
	}

	// 3. Mint a secret on create or explicit rotate; otherwise carry the
	// existing ciphertext through untouched. An unrotated secret is never
	// decrypted -- nothing in this sub-project needs its plaintext.
	var plaintextSecret string
	if creating || req.RotateSecret {
		plaintextSecret, err = mintSecret()
		if err != nil {
			return nil, "", err
		}
		ciphertext, encErr := common.EncryptSecret(plaintextSecret)
		if encErr != nil {
			return nil, "", fmt.Errorf("encrypt webhook signing secret: %w", encErr)
		}
		cfg.SigningSecretEncrypted = ciphertext
	} else {
		cfg.SigningSecretEncrypted = existing.SigningSecretEncrypted
	}

	// 4. Resolve identity, timestamps and the enabled flag.
	if creating {
		cfg.ID = uuid.New()
		cfg.CreatedAt = now
		cfg.Enabled = true
	} else {
		cfg.ID = existing.ID
		cfg.CreatedAt = existing.CreatedAt
		cfg.Enabled = existing.Enabled
	}
	if req.Enabled != nil {
		cfg.Enabled = *req.Enabled
	}

	// 5. Persist, and return the plaintext only if this call minted one.
	if err := s.repo.Upsert(ctx, cfg); err != nil {
		return nil, "", err
	}
	// Audit trail for the one vault-management mutation on this tier that
	// controls where future notifications are sent and what secret signs
	// them -- see the sibling create/update/delete/recover/purge
	// LogAuditInfo calls in vault_service.go. The message NEVER carries the
	// signing secret, plaintext or ciphertext, only vault id / url / whether
	// this was a create vs update / whether the secret rotated.
	if s.log != nil {
		operation := "update_vault_webhook"
		verb := "updated"
		if creating {
			operation = "create_vault_webhook"
			verb = "created"
		}
		rotated := plaintextSecret != ""
		s.log.LogAuditInfo(actor.String(), operation, "success",
			fmt.Sprintf("Vault webhook config %s: vault=%s url=%s rotated=%t", verb, vaultID, req.URL, rotated))
	}

	return cfg, plaintextSecret, nil
}

// Get returns the vault's webhook config.
func (s *vaultWebhookService) Get(ctx context.Context, vaultID uuid.UUID) (*model.VaultWebhookConfig, error) {
	cfg, err := s.repo.GetByVaultID(ctx, vaultID)
	if err != nil {
		if errors.Is(err, repositories.ErrNotFound) {
			return nil, fmt.Errorf("vault %s: %w", vaultID, ErrWebhookNotFound)
		}
		return nil, err
	}
	return cfg, nil
}

// Delete removes the vault's webhook config.
func (s *vaultWebhookService) Delete(ctx context.Context, vaultID uuid.UUID, actor uuid.UUID) error {
	if err := s.repo.DeleteByVaultID(ctx, vaultID); err != nil {
		return err
	}
	if s.log != nil {
		s.log.LogAuditInfo(actor.String(), "delete_vault_webhook", "success",
			fmt.Sprintf("Vault webhook config deleted: vault=%s", vaultID))
	}
	return nil
}
