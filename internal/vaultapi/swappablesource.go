package vaultapi

import (
	"context"
	"sync"
)

// SwappableSource is a TokenSource whose backing source can be replaced at
// runtime -- e.g. an in-chat login swapping a server's identity without
// restarting the process. Token calls always delegate to whatever source is
// current at the time of the call.
type SwappableSource struct {
	mu      sync.RWMutex
	current TokenSource
}

// NewSwappableSource wraps initial so it can be replaced later via Set.
func NewSwappableSource(initial TokenSource) *SwappableSource {
	return &SwappableSource{current: initial}
}

// Token delegates to whatever source is current.
func (s *SwappableSource) Token(ctx context.Context) (string, error) {
	s.mu.RLock()
	current := s.current
	s.mu.RUnlock()
	return current.Token(ctx)
}

// Set replaces the current source. Every Token call after this returns uses
// next; a call already in flight when Set runs still completes against
// whichever source it read.
func (s *SwappableSource) Set(next TokenSource) {
	s.mu.Lock()
	s.current = next
	s.mu.Unlock()
}
