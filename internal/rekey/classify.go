package rekey

import (
	"errors"
	"fmt"
	"strings"

	"rocketvault/common"
)

// ErrUndecryptable means a stored value opened with neither the old nor the
// new master key. Almost always a wrong --old-key-env; possibly a row sealed
// with a third, unknown key.
var ErrUndecryptable = errors.New("value decrypts with neither the old nor the new master key")

// action is what a rotation run must do with one stored value.
type action int

const (
	// actionInvalid is the zero value, so an action that was never assigned is
	// never a valid instruction. Every error path returns it: the destructive
	// action must not be what a caller sees if it reads the action before the
	// error. Mirrors ScopeInvalid in model/scope.go.
	actionInvalid action = iota
	// actionReEncrypt means the value opened with the old key and must be resealed.
	actionReEncrypt
	// actionAlreadyNewKey means the value already opens with the new key.
	actionAlreadyNewKey
	// actionSkipExternal means the value is a PKCS#11 handle, not ciphertext.
	actionSkipExternal
)

// classify decides what to do with a single stored value.
//
// The new key is tried before the old key, and that ordering is what makes a
// rotation safe to interrupt: AES-GCM is authenticated, so opening with the
// new key succeeding is a reliable "this row was already migrated" signal. No
// marker column or progress file is needed, and re-running after a crash
// simply skips the rows that are already done.
//
// The decrypted plaintext lives only as a local here and is passed straight
// back into EncryptWithKey. It is never logged, returned, or put in an error.
//
// Parameters:
//
//	value: The stored column value.
//	oldKey: The current 32-byte master key.
//	newKey: The replacement 32-byte master key.
//
// Returns:
//
//	The action to take, the resealed value (only for actionReEncrypt), and an
//	error if the value opens with neither key.
func classify(value string, oldKey, newKey []byte) (action, string, error) {
	if strings.HasPrefix(value, ExternalKeyPrefix) {
		return actionSkipExternal, "", nil
	}

	if _, err := common.DecryptWithKey(value, newKey); err == nil {
		return actionAlreadyNewKey, "", nil
	}

	plaintext, err := common.DecryptWithKey(value, oldKey)
	if err != nil {
		return actionInvalid, "", ErrUndecryptable
	}

	resealed, err := common.EncryptWithKey(plaintext, newKey)
	if err != nil {
		return actionInvalid, "", fmt.Errorf("re-encrypt with the new master key: %w", err)
	}

	return actionReEncrypt, resealed, nil
}
