// Package keycache provides an in-process cache for parsed cryptographic key
// material, eliminating repeated AES-GCM decryption and PEM parsing on hot paths.
package keycache

import (
	"crypto"

	"github.com/google/uuid"
)

// PEMKey wraps a raw PEM string stored as decrypted key material in the cache.
// Using a named type prevents accidental misinterpretation as a parsed crypto.PrivateKey.
type PEMKey struct{ PEM string }

// Entry holds parsed key material for one (keyID, version) pair.
type Entry struct {
	PrivateKey crypto.PrivateKey // nil for public-only keys
	PublicKey  crypto.PublicKey  // may be nil for symmetric keys
	KeyType    string            // model.KeyTypeRSA / ECDSA / ES256K / oct
	Version    int
}

// Clone returns a shallow copy of e. Safe because PrivateKey/PublicKey hold
// either nil or a PEMKey{PEM: string} — Go strings are immutable, so copying
// the interface value copies a read-only reference, not mutable state.
func (e *Entry) Clone() *Entry {
	cp := *e
	return &cp
}

// Zero clears key material in place. Called by cachekit after an entry is
// removed (TTL expiry, LRU eviction, invalidation) to shrink the in-memory
// exposure window rather than waiting for GC.
func (e *Entry) Zero() {
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
