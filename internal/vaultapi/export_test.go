package vaultapi

import "time"

// cachedTokenForTest exposes the cached token to same-package tests.
func (s *ServiceAccountSource) cachedTokenForTest() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token
}

// expiryForTest exposes the cached expiry to same-package tests.
func (s *ServiceAccountSource) expiryForTest() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expiresAt
}
