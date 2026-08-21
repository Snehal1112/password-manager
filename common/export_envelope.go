package common

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// exportFormatVersion is both the format marker and its version. Readers refuse
// a version they do not know rather than misparsing a future format.
const exportFormatVersion = 1

// Argon2id cost parameters. They are written into every envelope so that
// raising them later does not strand existing export files.
const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16
)

// ErrWrongPassphrase is returned when an export cannot be opened with the
// supplied passphrase. It deliberately does not distinguish a wrong passphrase
// from a corrupted file, since GCM cannot tell them apart.
var ErrWrongPassphrase = errors.New("wrong passphrase or corrupted export file")

// ErrUnsupportedExportVersion is returned for an envelope written by a newer
// RocketVault than this one.
var ErrUnsupportedExportVersion = errors.New("unsupported export format version")

type argonParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
}

type exportEnvelope struct {
	Version    int         `json:"rocketvault_export"`
	KDF        string      `json:"kdf"`
	Params     argonParams `json:"params"`
	Salt       string      `json:"salt"`
	Ciphertext string      `json:"ciphertext"`
}

// SealExport encrypts plaintext under a key derived from passphrase and returns
// a self-describing JSON envelope.
func SealExport(plaintext []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("a passphrase is required to seal an export")
	}

	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	// EncryptWithKey already does AES-256-GCM with a random nonce and returns
	// base64, so the nonce travels inside the ciphertext field.
	ciphertext, err := EncryptWithKey(string(plaintext), key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt export: %w", err)
	}

	return json.MarshalIndent(exportEnvelope{
		Version:    exportFormatVersion,
		KDF:        "argon2id",
		Params:     argonParams{Time: argonTime, Memory: argonMemory, Threads: argonThreads},
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Ciphertext: ciphertext,
	}, "", "  ")
}

// OpenExport reverses SealExport.
func OpenExport(data []byte, passphrase string) ([]byte, error) {
	var env exportEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("not a RocketVault export file: %w", err)
	}
	if env.Version != exportFormatVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedExportVersion, env.Version)
	}
	if env.KDF != "argon2id" {
		return nil, fmt.Errorf("unsupported key derivation function %q", env.KDF)
	}

	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil {
		return nil, fmt.Errorf("malformed salt: %w", err)
	}

	key := argon2.IDKey([]byte(passphrase), salt, env.Params.Time, env.Params.Memory, env.Params.Threads, argonKeyLen)

	plaintext, err := DecryptWithKey(env.Ciphertext, key)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return []byte(plaintext), nil
}

// IsSealedExport reports whether data looks like an envelope written by
// SealExport, so callers can decide whether a passphrase is needed.
func IsSealedExport(data []byte) bool {
	var probe struct {
		Version int `json:"rocketvault_export"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.Version != 0
}
