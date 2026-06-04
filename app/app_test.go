package app

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/internal/logging"
	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/server"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newLogger() *logging.Logger {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return &logging.Logger{Logger: l}
}

// newTestServer creates a server pointed at addr (may be invalid for error paths).
func newTestServer(addr string) *server.Server {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return server.NewDefaultServer(l, addr)
}

// ---------------------------------------------------------------------------
// Minimal mock scheduler that satisfies SchedulerServiceInterface
// ---------------------------------------------------------------------------

type mockScheduler struct {
	mock.Mock
}

func (m *mockScheduler) Start(ctx context.Context, interval time.Duration) error {
	return m.Called(ctx, interval).Error(0)
}

func (m *mockScheduler) Stop() error {
	return m.Called().Error(0)
}

func (m *mockScheduler) IsRunning() bool { return false }

func (m *mockScheduler) ProcessUserRotations(_ context.Context, _ uuid.UUID) error { return nil }

func (m *mockScheduler) ProcessUserReminders(_ context.Context, _ uuid.UUID) error { return nil }

func (m *mockScheduler) PerformManualRotation(_ context.Context, _ secretServices.ManualSchedulerRotationRequest) error {
	return nil
}

// ---------------------------------------------------------------------------
// TestNewTestApp_NoOptions
// ---------------------------------------------------------------------------

func TestNewTestApp_NoOptions(t *testing.T) {
	a := NewTestApp()
	assert.NotNil(t, a, "NewTestApp should return a non-nil App")
}

// ---------------------------------------------------------------------------
// Option tests
// ---------------------------------------------------------------------------

func TestWithBasePath(t *testing.T) {
	a := NewTestApp(WithBasePath("/api/v1"))
	assert.Equal(t, "/api/v1", a.basePath)
}

func TestWithDBName(t *testing.T) {
	a := NewTestApp(WithDBName("mydb.sqlite"))
	assert.Equal(t, "mydb.sqlite", a.databaseName)
}

func TestWithBackendEndPoint(t *testing.T) {
	a := NewTestApp(WithBackendEndPoint("http://localhost:9000"))
	assert.Equal(t, "http://localhost:9000", a.backendEndPoint)
}

func TestWithLogger(t *testing.T) {
	logger := newLogger()
	a := NewTestApp(WithLogger(logger))
	assert.Same(t, logger, a.Logger)
}

func TestWithSchedulerEnabled(t *testing.T) {
	interval := 30 * time.Minute
	a := NewTestApp(WithSchedulerEnabled(true, interval))
	assert.True(t, a.schedulerEnabled)
	assert.Equal(t, interval, a.schedulerInterval)
}

func TestWithSchedulerEnabled_Disabled(t *testing.T) {
	a := NewTestApp(WithSchedulerEnabled(false, 0))
	assert.False(t, a.schedulerEnabled)
}

func TestWithFrontendConfig(t *testing.T) {
	fc := &FrontendConfig{
		FeatureFlags: map[string]bool{"beta": true},
		PublicAPIURL: "https://api.example.com",
	}
	a := NewTestApp(WithFrontendConfig(fc))
	require.NotNil(t, a.FrontendConfig)
	assert.True(t, a.FrontendConfig.FeatureFlags["beta"])
	assert.Equal(t, "https://api.example.com", a.FrontendConfig.PublicAPIURL)
}

func TestWithServiceContainer(t *testing.T) {
	tc := testutils.NewTestContext(t)
	a := NewTestApp(WithServiceContainer(tc.MockContainer))
	assert.NotNil(t, a.ServiceContainer)
}

// ---------------------------------------------------------------------------
// TestWithServer / TestGetRouter
// ---------------------------------------------------------------------------

func TestWithServer(t *testing.T) {
	srv := newTestServer(":0")
	a := NewTestApp(WithServer(srv))
	require.NotNil(t, a.srv)
}

func TestGetRouter(t *testing.T) {
	srv := newTestServer(":0")
	a := NewTestApp(WithServer(srv))
	router := a.GetRouter()
	assert.NotNil(t, router, "GetRouter should return the server's router")
	assert.Same(t, srv.Router, router)
}

// ---------------------------------------------------------------------------
// TestStartServer_InvalidAddr_NoScheduler
// Exercises the path where schedulerEnabled=false → directly calls srv.StartServer.
// ---------------------------------------------------------------------------

func TestStartServer_InvalidAddr_NoScheduler(t *testing.T) {
	a := NewTestApp(
		WithServer(newTestServer("INVALID:ADDR:FORMAT")),
		WithSchedulerEnabled(false, 0),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := a.StartServer(ctx)
	assert.Error(t, err, "StartServer should fail for an invalid listen address")
}

// ---------------------------------------------------------------------------
// TestStartServer_WithScheduler_NilContainer
// schedulerEnabled=true but ServiceContainer is nil — the scheduler block is
// skipped entirely, so only the listen error is returned.
// ---------------------------------------------------------------------------

func TestStartServer_WithScheduler_NilContainer(t *testing.T) {
	a := NewTestApp(
		WithServer(newTestServer("INVALID:ADDR:FORMAT")),
		WithLogger(newLogger()),
		WithSchedulerEnabled(true, time.Minute),
		// No WithServiceContainer → a.ServiceContainer == nil
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := a.StartServer(ctx)
	assert.Error(t, err, "StartServer should fail on bad listen addr even with scheduler enabled")
}

// ---------------------------------------------------------------------------
// TestStartServer_WithScheduler_StartSucceeds
// Container returns a typed, valid scheduler; Start and Stop are both called.
// ---------------------------------------------------------------------------

func TestStartServer_WithScheduler_StartSucceeds(t *testing.T) {
	sched := &mockScheduler{}
	sched.On("Start", mock.Anything, mock.Anything).Return(nil)
	sched.On("Stop").Return(nil)

	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetSchedulerService").Return(sched)

	// Pre-cancel the context so the shutdown goroutine's <-ctx.Done() fires
	// immediately, allowing Stop() to be called before the test exits.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	a := NewTestApp(
		WithServer(newTestServer("INVALID:ADDR:FORMAT")),
		WithLogger(newLogger()),
		WithSchedulerEnabled(true, time.Minute),
		WithServiceContainer(tc.MockContainer),
	)

	err := a.StartServer(ctx)
	assert.Error(t, err) // invalid listen address
	sched.AssertCalled(t, "Start", mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// TestStartServer_WithScheduler_StartFails
// Scheduler.Start returns an error — the error is logged but the goroutine
// for Stop() is still spawned.  We cancel the context to let it complete.
// ---------------------------------------------------------------------------

func TestStartServer_WithScheduler_StartFails(t *testing.T) {
	sched := &mockScheduler{}
	sched.On("Start", mock.Anything, mock.Anything).Return(assert.AnError)
	sched.On("Stop").Return(nil) // Stop is always called by the goroutine when ctx is done

	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetSchedulerService").Return(sched)

	// Pre-cancel so the goroutine's <-ctx.Done() fires immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	a := NewTestApp(
		WithServer(newTestServer("INVALID:ADDR:FORMAT")),
		WithLogger(newLogger()),
		WithSchedulerEnabled(true, time.Minute),
		WithServiceContainer(tc.MockContainer),
	)

	err := a.StartServer(ctx)
	assert.Error(t, err) // invalid listen address
	sched.AssertCalled(t, "Start", mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// TestWithSchedulerEnabled_ZeroInterval
// When schedulerInterval==0, StartServer applies a default of 1 hour.
// ---------------------------------------------------------------------------

func TestWithSchedulerEnabled_ZeroInterval(t *testing.T) {
	sched := &mockScheduler{}
	sched.On("Start", mock.Anything, time.Hour).Return(nil)
	sched.On("Stop").Return(nil)

	tc := testutils.NewTestContext(t)
	tc.MockContainer.On("GetSchedulerService").Return(sched)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	a := NewTestApp(
		WithServer(newTestServer("INVALID:ADDR:FORMAT")),
		WithLogger(newLogger()),
		WithSchedulerEnabled(true, 0), // zero → defaults to 1h
		WithServiceContainer(tc.MockContainer),
	)

	_ = a.StartServer(ctx)
	sched.AssertCalled(t, "Start", mock.Anything, time.Hour)
}

// ---------------------------------------------------------------------------
// TestFrontendConfig_ZeroValue
// ---------------------------------------------------------------------------

func TestFrontendConfig_ZeroValue(t *testing.T) {
	var fc FrontendConfig
	assert.Nil(t, fc.FeatureFlags)
	assert.Empty(t, fc.PublicAPIURL)
	assert.Empty(t, fc.SentryDSN)
}

// ---------------------------------------------------------------------------
// TestWithMultipleOptions — options compose correctly in a single app.
// ---------------------------------------------------------------------------

func TestWithMultipleOptions(t *testing.T) {
	logger := newLogger()
	srv := newTestServer(":0")

	a := NewTestApp(
		WithBasePath("/v2"),
		WithDBName("test.db"),
		WithLogger(logger),
		WithServer(srv),
		WithSchedulerEnabled(false, 0),
	)

	assert.Equal(t, "/v2", a.basePath)
	assert.Equal(t, "test.db", a.databaseName)
	assert.Same(t, logger, a.Logger)
	assert.Same(t, srv, a.srv)
	assert.False(t, a.schedulerEnabled)
}

// ---------------------------------------------------------------------------
// TestWithBackendEndPoint_Empty — zero-value back-end endpoint.
// ---------------------------------------------------------------------------

func TestWithBackendEndPoint_Empty(t *testing.T) {
	a := NewTestApp(WithBackendEndPoint(""))
	assert.Equal(t, "", a.backendEndPoint)
}

// ---------------------------------------------------------------------------
// TestNewTestApp_OptionsApplied — all option setters exercise via NewTestApp.
// ---------------------------------------------------------------------------

func TestNewTestApp_OptionsApplied(t *testing.T) {
	tc := testutils.NewTestContext(t)
	srv := newTestServer(":0")
	logger := newLogger()
	fc := &FrontendConfig{SentryDSN: "https://sentry.io/123"}

	a := NewTestApp(
		WithBasePath("/root"),
		WithDBName("rocket.db"),
		WithBackendEndPoint("https://backend.example.com"),
		WithServer(srv),
		WithLogger(logger),
		WithSchedulerEnabled(true, 15*time.Minute),
		WithFrontendConfig(fc),
		WithServiceContainer(tc.MockContainer),
	)

	assert.Equal(t, "/root", a.basePath)
	assert.Equal(t, "rocket.db", a.databaseName)
	assert.Equal(t, "https://backend.example.com", a.backendEndPoint)
	assert.Same(t, srv, a.srv)
	assert.Same(t, logger, a.Logger)
	assert.True(t, a.schedulerEnabled)
	assert.Equal(t, 15*time.Minute, a.schedulerInterval)
	assert.Equal(t, "https://sentry.io/123", a.FrontendConfig.SentryDSN)
	assert.NotNil(t, a.ServiceContainer)
}
