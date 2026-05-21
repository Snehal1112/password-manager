package vaultclient

import "time"

// ExpireTokenForTest sets the cached token's expiry to the past so the next
// ensureToken call treats it as expired. Only for use in tests.
func (c *Client) ExpireTokenForTest() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != nil {
		c.token.expiresAt = time.Now().Add(-1 * time.Second)
	}
}
