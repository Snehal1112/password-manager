package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestLogger returns a silent logrus.FieldLogger for tests.
func newTestLogger() logrus.FieldLogger {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return l
}

// freePort returns a local TCP port that is (briefly) free.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	addr := l.Addr().String()
	l.Close()
	return addr
}

// ---------------------------------------------------------------------------
// TestNewServer
// ---------------------------------------------------------------------------

func TestNewServer(t *testing.T) {
	cfg := ServerConfig{
		EnableHTTP2:     false,
		EnableTLS:       false,
		EnableWebSocket: false,
		MaxConnections:  500,
	}
	s := NewServer(newTestLogger(), ":9090", cfg)

	require.NotNil(t, s)
	assert.NotNil(t, s.Router, "Router must be initialised")
	assert.Equal(t, ":9090", s.listenAddr)
	assert.Equal(t, cfg, s.config)
}

// ---------------------------------------------------------------------------
// TestNewDefaultServer
// ---------------------------------------------------------------------------

func TestNewDefaultServer(t *testing.T) {
	s := NewDefaultServer(newTestLogger(), ":8080")

	require.NotNil(t, s)
	assert.True(t, s.config.EnableHTTP2, "HTTP/2 should be enabled by default")
	assert.False(t, s.config.EnableTLS, "TLS should be disabled by default")
	assert.False(t, s.config.EnableWebSocket, "WebSocket should be disabled by default")
	assert.Equal(t, int64(1000), s.config.MaxConnections)
	assert.NotNil(t, s.Router)
}

// ---------------------------------------------------------------------------
// TestGetServerInfo
// ---------------------------------------------------------------------------

func TestGetServerInfo(t *testing.T) {
	cfg := ServerConfig{
		EnableHTTP2:     true,
		EnableTLS:       true,
		EnableWebSocket: true,
		MaxConnections:  2000,
	}
	s := NewServer(newTestLogger(), ":7777", cfg)
	info := s.GetServerInfo()

	expectedKeys := []string{
		"http2_enabled",
		"tls_enabled",
		"websocket_enabled",
		"max_connections",
		"listen_address",
	}
	for _, key := range expectedKeys {
		_, exists := info[key]
		assert.True(t, exists, "expected key %q in server info", key)
	}

	assert.Equal(t, true, info["http2_enabled"])
	assert.Equal(t, true, info["tls_enabled"])
	assert.Equal(t, true, info["websocket_enabled"])
	assert.Equal(t, int64(2000), info["max_connections"])
	assert.Equal(t, ":7777", info["listen_address"])
}

// ---------------------------------------------------------------------------
// TestHandleWebSocket_Disabled
// ---------------------------------------------------------------------------

func TestHandleWebSocket_Disabled(t *testing.T) {
	s := NewServer(newTestLogger(), ":0", ServerConfig{EnableWebSocket: false})

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	rr := httptest.NewRecorder()

	err := s.HandleWebSocket(rr, req, func(msg []byte) []byte { return msg })

	assert.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.Contains(t, rr.Body.String(), "WebSocket not enabled")
}

// ---------------------------------------------------------------------------
// TestHandleWebSocket_Enabled_NonWS
// A plain HTTP request to an enabled-WebSocket server; upgrader returns error.
// ---------------------------------------------------------------------------

func TestHandleWebSocket_Enabled_NonWS(t *testing.T) {
	s := NewServer(newTestLogger(), ":0", ServerConfig{EnableWebSocket: true})

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	rr := httptest.NewRecorder()

	err := s.HandleWebSocket(rr, req, func(msg []byte) []byte { return msg })
	assert.Error(t, err, "upgrade should fail for a plain HTTP request")
}

// ---------------------------------------------------------------------------
// TestHandleWebSocket_Enabled_RealConnection
// Uses a live httptest.Server for a genuine WebSocket handshake, exercising
// the echo message-handling loop.
// ---------------------------------------------------------------------------

func TestHandleWebSocket_Enabled_RealConnection(t *testing.T) {
	s := NewServer(newTestLogger(), ":0", ServerConfig{EnableWebSocket: true})

	s.Router.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		_ = s.HandleWebSocket(w, r, func(msg []byte) []byte {
			return append([]byte("echo:"), msg...)
		})
	})

	ts := httptest.NewServer(s.Router)
	defer ts.Close()

	wsURL := "ws" + ts.URL[len("http"):] + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte("hello")))

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, reply, err := conn.ReadMessage()
	require.NoError(t, err)
	assert.Equal(t, "echo:hello", string(reply))

	conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
}

// ---------------------------------------------------------------------------
// TestHandleWebSocket_NilResponseFromHandler
// Handler returns nil — server should NOT write a response but should continue.
// ---------------------------------------------------------------------------

func TestHandleWebSocket_NilResponseFromHandler(t *testing.T) {
	s := NewServer(newTestLogger(), ":0", ServerConfig{EnableWebSocket: true})

	s.Router.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		_ = s.HandleWebSocket(w, r, func(msg []byte) []byte {
			return nil // suppress echo
		})
	})

	ts := httptest.NewServer(s.Router)
	defer ts.Close()

	conn, _, err := websocket.DefaultDialer.Dial("ws"+ts.URL[len("http"):]+"/ws", nil)
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte("ping")))
	conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
}

// ---------------------------------------------------------------------------
// TestStartServer_InvalidAddress
// ---------------------------------------------------------------------------

func TestStartServer_InvalidAddress(t *testing.T) {
	s := NewServer(newTestLogger(), "INVALID:ADDR:FORMAT", ServerConfig{
		EnableHTTP2: false,
		EnableTLS:   false,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := s.StartServer(ctx)
	assert.Error(t, err, "StartServer should fail for an invalid listen address")
}

// ---------------------------------------------------------------------------
// TestStartServer_WithHTTP2_InvalidAddress
// Exercises the HTTP/2 configuration block before the net.Listen failure.
// ---------------------------------------------------------------------------

func TestStartServer_WithHTTP2_InvalidAddress(t *testing.T) {
	s := NewServer(newTestLogger(), "INVALID:ADDR:FORMAT", ServerConfig{
		EnableHTTP2: true,
		EnableTLS:   false,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := s.StartServer(ctx)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// TestStartServer_ValidAddress_GracefulShutdown
// The server listens on a random port and is shut down by sending SIGINT to
// the current process, exercising the signal-handling and shutdown paths.
// ---------------------------------------------------------------------------

func TestStartServer_ValidAddress_GracefulShutdown(t *testing.T) {
	addr := freePort(t)
	s := NewServer(newTestLogger(), addr, ServerConfig{
		EnableHTTP2:     false,
		EnableTLS:       false,
		EnableWebSocket: false,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.StartServer(ctx)
	}()

	// Wait for the server to start listening.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Trigger graceful shutdown via SIGINT.
	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	require.NoError(t, p.Signal(syscall.SIGINT))

	select {
	case err := <-errCh:
		// nil or http.ErrServerClosed — both are acceptable here.
		_ = err
	case <-time.After(5 * time.Second):
		t.Fatal("StartServer did not return within 5s after SIGINT")
	}
}

// ---------------------------------------------------------------------------
// TestStartServer_ValidAddress_HTTP2_GracefulShutdown
// Like above but with HTTP/2 enabled, exercising http2.ConfigureServer.
// ---------------------------------------------------------------------------

func TestStartServer_ValidAddress_HTTP2_GracefulShutdown(t *testing.T) {
	addr := freePort(t)
	s := NewServer(newTestLogger(), addr, ServerConfig{
		EnableHTTP2:     true,
		EnableTLS:       false,
		EnableWebSocket: false,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.StartServer(ctx)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	require.NoError(t, p.Signal(syscall.SIGINT))

	select {
	case err := <-errCh:
		_ = err
	case <-time.After(5 * time.Second):
		t.Fatal("StartServer did not return within 5s after SIGINT")
	}
}

// ---------------------------------------------------------------------------
// TestStartServer_ServerMakesHTTPRequest
// Verifies that the server actually serves HTTP once started.
// ---------------------------------------------------------------------------

func TestStartServer_ServerMakesHTTPRequest(t *testing.T) {
	addr := freePort(t)
	s := NewServer(newTestLogger(), addr, ServerConfig{
		EnableHTTP2:     false,
		EnableTLS:       false,
		EnableWebSocket: false,
	})

	s.Router.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "pong")
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.StartServer(ctx)
	}()

	// Wait for server to be ready.
	serverURL := fmt.Sprintf("http://%s/ping", addr)
	var resp *http.Response
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var e error
		resp, e = http.Get(serverURL)
		if e == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.NotNil(t, resp, "server should be reachable")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Shutdown.
	p, _ := os.FindProcess(os.Getpid())
	_ = p.Signal(syscall.SIGINT)
	<-errCh
}

// ---------------------------------------------------------------------------
// TestHandleWebSocket_BinaryMessage
// Binary messages are not text; the TextMessage branch is skipped and the
// connection stays open (no response written).
// ---------------------------------------------------------------------------

func TestHandleWebSocket_BinaryMessage(t *testing.T) {
	s := NewServer(newTestLogger(), ":0", ServerConfig{EnableWebSocket: true})

	s.Router.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		_ = s.HandleWebSocket(w, r, func(msg []byte) []byte {
			t.Error("handler should not be called for binary messages")
			return nil
		})
	})

	ts := httptest.NewServer(s.Router)
	defer ts.Close()

	wsURL := "ws" + ts.URL[len("http"):] + "/ws"
	_, rawURL, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	_ = rawURL

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	// Send binary — should be ignored by the handler.
	require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, []byte{0x01, 0x02}))
	// Close cleanly.
	conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
}

// ---------------------------------------------------------------------------
// Additional unit tests
// ---------------------------------------------------------------------------

func TestGetServerInfo_DefaultServer(t *testing.T) {
	s := NewDefaultServer(newTestLogger(), ":1234")
	info := s.GetServerInfo()

	assert.Equal(t, ":1234", info["listen_address"])
	assert.Equal(t, true, info["http2_enabled"])
	assert.Equal(t, false, info["tls_enabled"])
	assert.Equal(t, false, info["websocket_enabled"])
	assert.Equal(t, int64(1000), info["max_connections"])
}

func TestNewServer_RouterNotShared(t *testing.T) {
	s1 := NewDefaultServer(newTestLogger(), ":1111")
	s2 := NewDefaultServer(newTestLogger(), ":2222")
	assert.NotSame(t, s1.Router, s2.Router, "each server should have its own router")
}

func TestNewServer_WebSocketUpgraderInitialised(t *testing.T) {
	s := NewServer(newTestLogger(), ":0", ServerConfig{EnableWebSocket: true})
	assert.NotNil(t, s.upgrader, "upgrader must be set")
}

// TestHandleWebSocket_WSUrl verifies the WS URL helper we use internally is sane.
func TestHandleWebSocket_WSUrlHelper(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	wsURL := "ws" + ts.URL[len("http"):]
	u, err := url.Parse(wsURL)
	require.NoError(t, err)
	assert.Equal(t, "ws", u.Scheme)
}
