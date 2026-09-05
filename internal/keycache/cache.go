// Package keycache provides an in-process cache for parsed cryptographic key
// material, eliminating repeated AES-GCM decryption and PEM parsing on hot paths.
package keycache

import (
	"crypto"

	"github.com/google/uuid"
)

// PEMKey wraps raw PEM bytes stored as decrypted key material in the cache.
// Using a named type prevents accidental misinterpretation as a parsed
// crypto.PrivateKey. Backed by []byte (not string) specifically so Zero()
// can overwrite the underlying bytes in place — a Go string is immutable, so
// a string-backed PEMKey could only ever drop the reference, not scrub it.
type PEMKey struct{ PEM []byte }

// Entry holds parsed key material for one (keyID, version) pair.
type Entry struct {
	PrivateKey crypto.PrivateKey // nil for public-only keys
	PublicKey  crypto.PublicKey  // may be nil for symmetric keys
	KeyType    string            // model.KeyTypeRSA / ECDSA / ES256K / oct
	Version    int
}

// clonePEMKeyField returns an independent copy of v: a deep copy of its
// backing byte slice if v holds a PEMKey (the only concrete type production
// code ever stores here), or v unchanged for nil/anything else. Needed
// because []byte is a mutable, shared backing array — unlike the string it
// replaced, copying the PEMKey struct alone would still alias the same
// bytes, so Zero() on one clone would corrupt every other clone's view.
func clonePEMKeyField(v any) any {
	pk, ok := v.(PEMKey)
	if !ok {
		return v
	}
	cp := make([]byte, len(pk.PEM))
	copy(cp, pk.PEM)
	return PEMKey{PEM: cp}
}

// Clone returns a copy of e that shares no mutable state with the original.
func (e *Entry) Clone() *Entry {
	cp := *e
	cp.PrivateKey = clonePEMKeyField(e.PrivateKey)
	cp.PublicKey = clonePEMKeyField(e.PublicKey)
	return &cp
}

// zeroPEMKeyField overwrites v's underlying bytes with zeroes if v holds a
// PEMKey, so the plaintext does not linger in freed heap memory waiting on
// GC.
func zeroPEMKeyField(v any) {
	if pk, ok := v.(PEMKey); ok {
		for i := range pk.PEM {
			pk.PEM[i] = 0
		}
	}
}

// Zero clears key material in place. Called by cachekit after an entry is
// removed (TTL expiry, LRU eviction, invalidation) to shrink the in-memory
// exposure window rather than waiting for GC.
func (e *Entry) Zero() {
	zeroPEMKeyField(e.PrivateKey)
	zeroPEMKeyField(e.PublicKey)
	e.PrivateKey = nil
	e.PublicKey = nil
}

// CacheStats holds observable cache counters.
type CacheStats struct {
	TotalEntries   int
	ExpiredEntries int
}

// Cache is the interface all key-cache implementations must satisfy.
type Cache interface {
	// Get returns the entry for (keyID, version) if present and unexpired.
	Get(keyID uuid.UUID, version int) (*Entry, bool)
	// Set stores entry under (keyID, version).
	Set(keyID uuid.UUID, version int, entry *Entry)
	// Invalidate evicts all versions for keyID.
	Invalidate(keyID uuid.UUID)
	// InvalidateAll evicts every entry.
	InvalidateAll()
	// Stats returns current counters without modifying state.
	Stats() CacheStats
	// Stop shuts down the background sweeper goroutine.
	Stop()
}
