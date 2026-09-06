package repositories

// WithMetricsForTest exposes the unexported withMetrics helper to the external
// repositories_test package. Test-only: the _test.go suffix keeps this out of
// the production build, so nothing ships an exported alias.
var WithMetricsForTest = withMetrics
