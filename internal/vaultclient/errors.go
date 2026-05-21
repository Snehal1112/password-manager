package vaultclient

import "errors"

// ErrSecretNotFound is returned when the vault responds with 404 for a secret.
var ErrSecretNotFound = errors.New("vaultclient: secret not found")

// ErrAuthFailed is returned when the vault rejects the client credentials (401).
var ErrAuthFailed = errors.New("vaultclient: authentication failed — check VAULT_CLIENT_ID and VAULT_CLIENT_SECRET")
