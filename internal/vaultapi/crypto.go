package vaultapi

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// SignResult is a signature produced by a vault-held key.
type SignResult struct {
	KeyID     uuid.UUID
	Algorithm string
	Signature []byte
	// Version is the key version actually used, which matters after a
	// rotation: verifying later requires the same one.
	Version int
}

// VerifyResult is the outcome of a signature check.
type VerifyResult struct {
	KeyID     uuid.UUID
	Algorithm string
	Valid     bool
	Version   int
}

// EncryptResult is ciphertext produced by a vault-held key.
type EncryptResult struct {
	KeyID      uuid.UUID
	Algorithm  string
	Ciphertext []byte
	// Nonce is present for AES-GCM and empty otherwise. Decryption requires
	// it, so losing it makes the ciphertext permanently undecryptable.
	Nonce   []byte
	Version int
}

// DecryptResult is plaintext recovered by a vault-held key.
//
// Plaintext is a SecretValue rather than []byte, unlike Sign's signature.
// The asymmetry is the point: a signature is public, a decrypted plaintext is
// not. SecretValue redacts on String, GoString and MarshalJSON, so it cannot
// reach a log line or a marshalled response by accident.
type DecryptResult struct {
	KeyID     uuid.UUID
	Algorithm string
	Plaintext SecretValue
	Version   int
}

// cryptoBody is the request shape shared by the four crypto routes. Unused
// fields are omitted, so one type serves all of them.
type cryptoBody struct {
	Value     string `json:"value"`
	Signature string `json:"signature,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	// Version zero means the current version, which is what the server
	// assumes when the field is absent.
	Version int `json:"version,omitempty"`
}

// Sign signs data with a vault-held key.
//
// data and the returned signature are raw bytes. The API encodes both as
// base64, but that is a transport detail: exposing it would make every caller
// encode identically, and a caller that encoded already-encoded data would
// get a valid signature over the wrong bytes -- a failure that verifies
// correctly against itself and stays invisible until something external
// checks it.
//
// An empty algorithm is omitted rather than defaulted here. The server
// defaults to RS256 (api/keys.go:912), and leaving it as the single source of
// truth beats duplicating a value that could drift.
func (c *Client) Sign(ctx context.Context, vault, name string, data []byte, algorithm string, version int) (*SignResult, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to sign")
	}
	if name == "" {
		return nil, fmt.Errorf("vaultapi: key name is required to sign")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("vaultapi: data is required to sign")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindKeys, name)
	if err != nil {
		return nil, err
	}

	body := cryptoBody{
		Value:     base64.StdEncoding.EncodeToString(data),
		Algorithm: algorithm,
		Version:   version,
	}

	var wire struct {
		KeyID     string `json:"key_id"`
		Algorithm string `json:"algorithm"`
		Value     string `json:"value"`
		Version   int    `json:"version"`
	}
	path := fmt.Sprintf("/api/v1/vaults/%s/keys/%s/sign", vault, id)
	if err := c.Do(ctx, http.MethodPost, path, body, &wire); err != nil {
		return nil, err
	}

	signature, err := base64.StdEncoding.DecodeString(wire.Value)
	if err != nil {
		return nil, fmt.Errorf("vaultapi: signature was not valid base64: %w", err)
	}

	keyID, parseErr := uuid.Parse(wire.KeyID)
	if parseErr != nil {
		keyID = id
	}
	return &SignResult{
		KeyID:     keyID,
		Algorithm: wire.Algorithm,
		Signature: signature,
		Version:   wire.Version,
	}, nil
}

// Verify checks a signature against data.
//
// An invalid signature returns Valid false with a nil error: that is a
// successful call with a negative answer. Reporting it as an error would
// leave a caller unable to tell a forgery from an unreachable vault, which
// are opposite conclusions.
func (c *Client) Verify(ctx context.Context, vault, name string, data, signature []byte, algorithm string, version int) (*VerifyResult, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to verify")
	}
	if name == "" {
		return nil, fmt.Errorf("vaultapi: key name is required to verify")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("vaultapi: data is required to verify")
	}
	if len(signature) == 0 {
		return nil, fmt.Errorf("vaultapi: a signature is required to verify")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindKeys, name)
	if err != nil {
		return nil, err
	}

	body := cryptoBody{
		Value:     base64.StdEncoding.EncodeToString(data),
		Signature: base64.StdEncoding.EncodeToString(signature),
		Algorithm: algorithm,
		Version:   version,
	}

	var wire struct {
		KeyID     string `json:"key_id"`
		Algorithm string `json:"algorithm"`
		Valid     bool   `json:"valid"`
		Version   int    `json:"version"`
	}
	path := fmt.Sprintf("/api/v1/vaults/%s/keys/%s/verify", vault, id)
	if err := c.Do(ctx, http.MethodPost, path, body, &wire); err != nil {
		return nil, err
	}

	keyID, parseErr := uuid.Parse(wire.KeyID)
	if parseErr != nil {
		keyID = id
	}
	return &VerifyResult{
		KeyID:     keyID,
		Algorithm: wire.Algorithm,
		Valid:     wire.Valid,
		Version:   wire.Version,
	}, nil
}

// Encrypt encrypts plaintext with a vault-held key.
func (c *Client) Encrypt(ctx context.Context, vault, name string, plaintext []byte, algorithm string, version int) (*EncryptResult, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to encrypt")
	}
	if name == "" {
		return nil, fmt.Errorf("vaultapi: key name is required to encrypt")
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("vaultapi: plaintext is required to encrypt")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindKeys, name)
	if err != nil {
		return nil, err
	}

	body := cryptoBody{
		Value:     base64.StdEncoding.EncodeToString(plaintext),
		Algorithm: algorithm,
		Version:   version,
	}

	var wire struct {
		KeyID     string `json:"key_id"`
		Algorithm string `json:"algorithm"`
		Value     string `json:"value"`
		Nonce     string `json:"nonce"`
		Version   int    `json:"version"`
	}
	path := fmt.Sprintf("/api/v1/vaults/%s/keys/%s/encrypt", vault, id)
	if err := c.Do(ctx, http.MethodPost, path, body, &wire); err != nil {
		return nil, err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(wire.Value)
	if err != nil {
		return nil, fmt.Errorf("vaultapi: ciphertext was not valid base64: %w", err)
	}

	result := &EncryptResult{
		Algorithm:  wire.Algorithm,
		Ciphertext: ciphertext,
		Version:    wire.Version,
	}
	if wire.Nonce != "" {
		nonce, err := base64.StdEncoding.DecodeString(wire.Nonce)
		if err != nil {
			return nil, fmt.Errorf("vaultapi: nonce was not valid base64: %w", err)
		}
		result.Nonce = nonce
	}

	keyID, parseErr := uuid.Parse(wire.KeyID)
	if parseErr != nil {
		keyID = id
	}
	result.KeyID = keyID
	return result, nil
}

// Decrypt recovers plaintext with a vault-held key.
//
// nonce is required for AES-GCM and ignored otherwise; it comes from the
// EncryptResult that produced the ciphertext.
func (c *Client) Decrypt(ctx context.Context, vault, name string, ciphertext, nonce []byte, algorithm string, version int) (*DecryptResult, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to decrypt")
	}
	if name == "" {
		return nil, fmt.Errorf("vaultapi: key name is required to decrypt")
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("vaultapi: ciphertext is required to decrypt")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindKeys, name)
	if err != nil {
		return nil, err
	}

	body := cryptoBody{
		Value:     base64.StdEncoding.EncodeToString(ciphertext),
		Algorithm: algorithm,
		Version:   version,
	}
	if len(nonce) > 0 {
		body.Nonce = base64.StdEncoding.EncodeToString(nonce)
	}

	var wire struct {
		KeyID     string `json:"key_id"`
		Algorithm string `json:"algorithm"`
		Value     string `json:"value"`
		Version   int    `json:"version"`
	}
	path := fmt.Sprintf("/api/v1/vaults/%s/keys/%s/decrypt", vault, id)
	if err := c.Do(ctx, http.MethodPost, path, body, &wire); err != nil {
		return nil, err
	}

	plaintext, err := base64.StdEncoding.DecodeString(wire.Value)
	if err != nil {
		return nil, fmt.Errorf("vaultapi: plaintext was not valid base64: %w", err)
	}

	keyID, parseErr := uuid.Parse(wire.KeyID)
	if parseErr != nil {
		keyID = id
	}
	return &DecryptResult{
		KeyID:     keyID,
		Algorithm: wire.Algorithm,
		Plaintext: SecretValue(plaintext),
		Version:   wire.Version,
	}, nil
}
