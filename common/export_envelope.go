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

// ErrPassphraseRequired is returned when sealing or opening an export is
// attempted with an empty passphrase.
var ErrPassphraseRequired = errors.New("a passphrase is required to seal an export")

// Bounds on the argon2 params an export file is allowed to carry. The values
// are read straight from the (untrusted) file and passed to argon2.IDKey,
// which panics if time or threads is below 1, and which will happily try to
// allocate whatever memory value it is given. minParamMemory/maxParamMemory
// bracket the sealed value (argonMemory, 65536 KiB / 64 MiB) with enough room
// for a future cost increase while still rejecting a file that asks for an
// implausible amount of memory (e.g. a corrupted or malicious 4 GiB value).
const (
	minParamMemory  uint32 = 8 * 1024        // 8 MiB.
	maxParamMemory  uint32 = 1 * 1024 * 1024 // 1 GiB.
	minParamSaltLen int    = 8
	maxParamSaltLen int    = 64
)

// validateArgonParams checks argon2 parameters decoded from an untrusted
// envelope before they are used to derive a key. argon2.IDKey panics on a
// time or threads value below 1, and an unbounded memory value could exhaust
// host memory, so every field must be validated first.
func validateArgonParams(p argonParams, saltLen int) error {
	if p.Time < 1 {
		return fmt.Errorf("invalid export file: argon2 time parameter must be at least 1, got %d", p.Time)
	}
	if p.Threads < 1 {
		return fmt.Errorf("invalid export file: argon2 threads parameter must be at least 1, got %d", p.Threads)
	}
	if p.Memory < minParamMemory || p.Memory > maxParamMemory {
		return fmt.Errorf("invalid export file: argon2 memory parameter %d KiB is outside the allowed range [%d, %d] KiB", p.Memory, minParamMemory, maxParamMemory)
	}
	if saltLen < minParamSaltLen || saltLen > maxParamSaltLen {
		return fmt.Errorf("invalid export file: salt length %d bytes is outside the allowed range [%d, %d] bytes", saltLen, minParamSaltLen, maxParamSaltLen)
	}
	return nil
}

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
		return nil, ErrPassphraseRequired
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
	if passphrase == "" {
		return nil, ErrPassphraseRequired
	}

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

	// The params below came from the file itself, not from SealExport, so they
	// must be validated before argon2.IDKey ever sees them. Validation, not
	// ErrWrongPassphrase, is returned here: a malformed file is a different
	// problem than a wrong passphrase, and conflating them would hide it.
	if err := validateArgonParams(env.Params, len(salt)); err != nil {
		return nil, err
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
