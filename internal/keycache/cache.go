// Package keycache provides an in-process cache for parsed cryptographic key
// material, eliminating repeated AES-GCM decryption and PEM parsing on hot paths.
package keycache

import (
	"crypto"
	"time"

	"github.com/google/uuid"
)

// Entry holds parsed key material for one (keyID, version) pair.
type Entry struct {
	PrivateKey crypto.PrivateKey // nil for public-only keys
	PublicKey  crypto.PublicKey  // may be nil for symmetric keys
	KeyType    string            // model.KeyTypeRSA / ECDSA / ES256K / oct
	Version    int
	ExpiresAt  time.Time
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
