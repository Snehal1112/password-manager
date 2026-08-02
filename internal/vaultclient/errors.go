package vaultclient

import "errors"

// ErrSecretNotFound is returned when the vault responds with 404 for a secret.
var ErrSecretNotFound = errors.New("vaultclient: secret not found")

// ErrAuthFailed is returned when the vault rejects the client credentials (401).
var ErrAuthFailed = errors.New("vaultclient: authentication failed — check VAULT_CLIENT_ID and VAULT_CLIENT_SECRET")

// ErrNetwork is returned when a request to RocketVault fails at the transport
// level (DNS failure, connection refused, timeout, TLS handshake, etc.) and
// retries have been exhausted. Check with errors.Is.
var ErrNetwork = errors.New("vaultclient: network error")

// ErrUnexpectedStatus is returned when RocketVault responds with a status
// code other than the ones this package understands (200, 401, 404) and
// retries have been exhausted. Check with errors.Is.
var ErrUnexpectedStatus = errors.New("vaultclient: unexpected response status")

// ErrDecodeFailed is returned when a 200 response body cannot be decoded as
// the expected JSON shape. Not retried — a malformed body on a 200 status is
// treated as a permanent incompatibility, not a transient failure.
var ErrDecodeFailed = errors.New("vaultclient: failed to decode response")
