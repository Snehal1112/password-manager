package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"rocketvault/common"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

// newVaultRateLimitTestMiddleware builds a Middleware carrying only what
// VaultRateLimitMiddleware needs, so these tests do not depend on the service
// container.
func newVaultRateLimitTestMiddleware(perMinute int64, m VaultRateLimitRecorder) *Middleware {
	logger := &logging.Logger{Logger: logrus.New()}
	logger.SetLevel(logrus.ErrorLevel)

	return &Middleware{
		logger:            logger,
		vaultLimiter:      newKeyedRateLimiter(perMinute),
		vaultLimitMetrics: m,
	}
}

// requestForVault returns a request carrying vaultID as the resolved vault, as
// VaultResolutionMiddleware would have set it.
func requestForVault(vaultID string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	if vaultID != "" {
		req = req.WithContext(context.WithValue(req.Context(), common.VaultIDKey, vaultID))
	}
	return req
}

// countingRecorder records rejections so tests can assert on them.
type countingRecorder struct {
	vaults []string
}

func (c *countingRecorder) RecordVaultRateLimitRejection(vaultID string) {
	c.vaults = append(c.vaults, vaultID)
}

// TestVaultRateLimitMiddleware_OneVaultCannotExhaustAnother is the noisy-neighbor
// property: traffic against one vault must never consume another vault's budget.
func TestVaultRateLimitMiddleware_OneVaultCannotExhaustAnother(t *testing.T) {
	t.Parallel()
	mw := newVaultRateLimitTestMiddleware(3, nil)

	handler := mw.VaultRateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	const noisyVault = "11111111-1111-1111-1111-111111111111"
	const quietVault = "22222222-2222-2222-2222-222222222222"

	// Drain the noisy vault's whole budget.
	for i := 0; i < 3; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, requestForVault(noisyVault))
		assert.Equal(t, http.StatusOK, rr.Code, "noisy vault request %d should succeed", i+1)
	}

	// The next request to the noisy vault is rejected.
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, requestForVault(noisyVault))
	assert.Equal(t, http.StatusTooManyRequests, rr.Code, "noisy vault should be rate limited once its budget is spent")

	// The quiet vault is untouched — this is the whole point of the middleware.
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, requestForVault(quietVault))
	assert.Equal(t, http.StatusOK, rr.Code, "a different vault must not be affected by the noisy vault")
}

// TestVaultRateLimitMiddleware_MissingVaultIDUsesDefaultVault pins the fallback
// that PolicyMiddleware already uses: no resolved vault means the default vault.
func TestVaultRateLimitMiddleware_MissingVaultIDUsesDefaultVault(t *testing.T) {
	t.Parallel()
	mw := newVaultRateLimitTestMiddleware(2, nil)

	handler := mw.VaultRateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// One request with no vault in context, one naming the default vault
	// explicitly. They must share a bucket, leaving nothing for a third.
	for _, vaultID := range []string{"", model.DefaultVaultID} {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, requestForVault(vaultID))
		assert.Equal(t, http.StatusOK, rr.Code, "request for vault %q should succeed", vaultID)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, requestForVault(""))
	assert.Equal(t, http.StatusTooManyRequests, rr.Code,
		"an unresolved vault must share the default vault's bucket")
}

// TestVaultRateLimitMiddleware_SetsVaultHeaders verifies the per-vault budget is
// reported under its own header names, so it cannot clobber the per-IP limiter's
// X-RateLimit-* headers written earlier in the chain.
func TestVaultRateLimitMiddleware_SetsVaultHeaders(t *testing.T) {
	t.Parallel()
	mw := newVaultRateLimitTestMiddleware(10, nil)

	handler := mw.VaultRateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	const vaultID = "33333333-3333-3333-3333-333333333333"

	rr1 := httptest.NewRecorder()
	// Pre-set the per-IP headers the earlier middleware would have written.
	rr1.Header().Set("X-RateLimit-Limit", "300")
	handler.ServeHTTP(rr1, requestForVault(vaultID))

	assert.Equal(t, "10", rr1.Header().Get("X-RateLimit-Vault-Limit"))
	assert.Equal(t, "300", rr1.Header().Get("X-RateLimit-Limit"),
		"the per-vault limiter must not overwrite the per-IP limiter's headers")

	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, requestForVault(vaultID))

	rem1, err := strconv.Atoi(rr1.Header().Get("X-RateLimit-Vault-Remaining"))
	assert.NoError(t, err)
	rem2, err := strconv.Atoi(rr2.Header().Get("X-RateLimit-Vault-Remaining"))
	assert.NoError(t, err)
	assert.Equal(t, rem1-1, rem2, "successive requests to one vault must draw down the same bucket")
}

// TestVaultRateLimitMiddleware_RecordsRejection verifies a rejected request is
// reported to the metrics recorder, labelled with the vault that was throttled.
func TestVaultRateLimitMiddleware_RecordsRejection(t *testing.T) {
	t.Parallel()
	rec := &countingRecorder{}
	mw := newVaultRateLimitTestMiddleware(1, rec)

	handler := mw.VaultRateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	const vaultID = "44444444-4444-4444-4444-444444444444"

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, requestForVault(vaultID))
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Empty(t, rec.vaults, "an allowed request must not be recorded as a rejection")

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, requestForVault(vaultID))
	assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	assert.Equal(t, []string{vaultID}, rec.vaults, "the rejected vault must be recorded once")
}

// TestVaultRateLimitMiddleware_SkipsHealthProbes pins that health probes are
// exempt. VaultResolutionMiddleware skips them, so they have no vault of their
// own — counting them would let a liveness probe drain the default vault's
// budget and throttle real traffic.
func TestVaultRateLimitMiddleware_SkipsHealthProbes(t *testing.T) {
	t.Parallel()
	mw := newVaultRateLimitTestMiddleware(1, nil)

	handler := mw.VaultRateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	probes := []string{
		"/api/v1/health",
		"/api/v1/health/ready",
		"/api/v1/health/live",
		"/api/v1/health/database",
	}

	// Far more probe requests than the budget of 1 — none may be rejected.
	for _, path := range probes {
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusOK, rr.Code, "%s request %d must not be rate limited", path, i+1)
			assert.Empty(t, rr.Header().Get("X-RateLimit-Vault-Limit"),
				"%s carries no vault, so it must not report a vault budget", path)
		}
	}

	// The default vault's budget is untouched by all those probes.
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, requestForVault(model.DefaultVaultID))
	assert.Equal(t, http.StatusOK, rr.Code, "health probes must not have spent the default vault's budget")
}

// TestVaultRateLimitMiddleware_NilMetricsRecorderIsSafe pins that metrics are
// optional — the middleware must not panic when no recorder is wired up.
func TestVaultRateLimitMiddleware_NilMetricsRecorderIsSafe(t *testing.T) {
	t.Parallel()
	mw := newVaultRateLimitTestMiddleware(1, nil)

	handler := mw.VaultRateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	const vaultID = "55555555-5555-5555-5555-555555555555"

	for range 2 {
		handler.ServeHTTP(httptest.NewRecorder(), requestForVault(vaultID))
	}
	// Reaching here without a panic is the assertion.
}
