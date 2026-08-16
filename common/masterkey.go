package common

import (
	"crypto/subtle"
	"fmt"
)

// compromisedDefaultKey is the placeholder master key that shipped in this
// repository's committed .rocketvault.yaml. It base64-decodes to the ASCII
// string "0123456789abcdef0123456789abcdef". A 2026-08-16 penetration test
// decrypted a live database with it, so any deployment still using it is
// considered breached.
var compromisedDefaultKey = []byte("0123456789abcdef0123456789abcdef")

// minDistinctBytes is the smallest number of distinct byte values a genuine
// 32-byte random key is expected to contain. Random keys average about 31
// distinct values, so the chance of rejecting a real CSPRNG key here is around
// 3e-10, while hand-made filler like "AAAA..." is caught immediately.
const minDistinctBytes = 16

// ValidateMasterKey reports whether a configured master key is safe to seal
// data with. It rejects a missing, malformed, or wrong-length key, the
// known-compromised committed default, keys that are entirely printable ASCII
// (typed by a human rather than produced by a CSPRNG), and keys with too few
// distinct byte values.
//
// The checks run most-specific-first so the operator sees the most actionable
// message. The key itself never appears in any returned error.
//
// Parameters:
//
//	encoded: The base64-encoded master key.
//
// Returns:
//
//	nil if the key is usable, otherwise an error explaining what to do.
func ValidateMasterKey(encoded string) error {
	key, err := ParseMasterKey(encoded)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(key, compromisedDefaultKey) == 1 {
		return fmt.Errorf("master key is the known-compromised default committed to this " +
			"repository (it decodes to \"0123456789abcdef0123456789abcdef\"); generate a new " +
			"key with \"openssl rand -base64 32\" and migrate existing data with " +
			"\"rocketvault master-key rotate\"")
	}

	if allPrintableASCII(key) {
		return fmt.Errorf("master key is entirely printable ASCII, which means it was typed " +
			"rather than generated; generate a new key with \"openssl rand -base64 32\" and " +
			"migrate existing data with \"rocketvault master-key rotate\"")
	}

	if distinctBytes(key) < minDistinctBytes {
		return fmt.Errorf("master key has fewer than %d distinct byte values, which no CSPRNG "+
			"output realistically has; generate a new key with \"openssl rand -base64 32\" and "+
			"migrate existing data with \"rocketvault master-key rotate\"", minDistinctBytes)
	}

	return nil
}

// allPrintableASCII reports whether every byte is a printable ASCII character.
func allPrintableASCII(key []byte) bool {
	for _, b := range key {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

// distinctBytes counts how many different byte values appear in key.
func distinctBytes(key []byte) int {
	var seen [256]bool
	count := 0
	for _, b := range key {
		if !seen[b] {
			seen[b] = true
			count++
		}
	}
	return count
}
