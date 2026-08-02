package vaultclient_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"rocketvault/internal/vaultclient"
)

// TestClient_ConcurrentGet_NoDataRace exercises the token cache from many
// goroutines simultaneously. Run with -race to prove the mutex is load-bearing.
func TestClient_ConcurrentGet_NoDataRace(t *testing.T) {
	srv := newTestServer(t, "concurrent-value")
	defer srv.Close()

	c, err := vaultclient.New(vaultclient.Config{
		URL: srv.URL, ClientID: "test-id", ClientSecret: "test-secret",
	})
	require.NoError(t, err)

	const goroutines = 50
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if _, err := c.Get(context.Background(), "some-uuid"); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("unexpected error from concurrent Get: %v", err)
	}
}
