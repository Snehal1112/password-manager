package vaultclient

import (
	"time"

	"rocketvault/internal/retry"
)

// ExpireTokenForTest sets the cached token's expiry to the past so the next
// ensureToken call treats it as expired. Only for use in tests.
func (c *Client) ExpireTokenForTest() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != nil {
		c.token.expiresAt = time.Now().Add(-1 * time.Second)
	}
}

// RetryPolicyForTest exposes the Client's resolved retry policy so tests can
// assert on how Config.RetryPolicy / viper's retry.external_services block
// were resolved. Only for use in tests.
func (c *Client) RetryPolicyForTest() retry.Policy {
	return c.retryPolicy
}
