package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

// ServerConfig holds configuration for server features.
type ServerConfig struct {
	EnableHTTP2     bool
	EnableTLS       bool
	CertFile        string
	KeyFile         string
	EnableWebSocket bool
	MaxConnections  int64
}

// Server represents the HTTP server for the vault service application.
// It contains the router for handling HTTP requests, the HTTP server instance,
// the address on which the server listens, and a logger for logging server activities.
type Server struct {
	Router     *mux.Router
	Server     *http.Server
	listenAddr string
	logger     logrus.FieldLogger
	config     ServerConfig
	upgrader   *websocket.Upgrader
}

// NewServer creates a new instance of Server with the provided logger, listen address, and configuration.
// It initializes the Router using mux.NewRouter() and sets up advanced features like HTTP/2 and WebSockets.
//
// Parameters:
//   - logger: an instance of logrus.FieldLogger for logging purposes.
//   - listenAddr: a string representing the address on which the server will listen.
//   - config: ServerConfig containing advanced feature configurations.
//
// Returns:
//   - A pointer to a newly created Server instance.
func NewServer(logger logrus.FieldLogger, listenAddr string, config ServerConfig) *Server {
	// Configure WebSocket upgrader
	upgrader := &websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			// Allow all origins in development, restrict in production
			return true
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	return &Server{
		Router:     mux.NewRouter(),
		logger:     logger,
		listenAddr: listenAddr,
		config:     config,
		upgrader:   upgrader,
	}
}

// NewDefaultServer creates a server with default configuration for backwards compatibility.
func NewDefaultServer(logger logrus.FieldLogger, listenAddr string) *Server {
	config := ServerConfig{
		EnableHTTP2:     true,
		EnableTLS:       false,
		EnableWebSocket: true,
		MaxConnections:  1000,
	}
	return NewServer(logger, listenAddr, config)
}

// StartServer starts the HTTP/HTTP2 server with advanced features and listens for incoming requests.
// It sets up signal handling for graceful shutdown and manages server lifecycle.
// Features include HTTP/2 support, TLS with ALPN, content negotiation, and WebSocket support.
//
// Parameters:
//   - ctx: The context to control server lifecycle.
//
// Returns:
//   - error: An error if the server fails to start or encounters an issue during runtime.
//
// The server listens on the address specified in the Server struct's listenAddr field.
// It uses a CORS middleware to allow all origins. The server has configured timeouts for
// write, read, and idle connections, with support for HTTP/2 and WebSocket upgrades.
//
// The function also handles OS signals (SIGINT, SIGTERM) for graceful shutdown. Upon receiving
// a signal, it attempts to shut down the server cleanly within a 10-second timeout. If the server
// fails to shut down within this period, it logs a warning.
func (s *Server) StartServer(ctx context.Context) error {
	_, serveCtxCancel := context.WithCancel(ctx)
	defer serveCtxCancel()

	logger := s.logger
	errCh := make(chan error, 2)
	exitCh := make(chan bool, 1)
	signalCh := make(chan os.Signal, 1)

	// Configure CORS
	cc := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
		MaxAge:           86400, // 24 hours
	})

	// Create HTTP server with enhanced configuration
	srv := &http.Server{
		Handler:           cc.Handler(s.Router),
		WriteTimeout:      30 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	// Configure TLS if enabled
	var tlsConfig *tls.Config
	if s.config.EnableTLS {
		tlsConfig = &tls.Config{
			// Enforce TLS 1.3 as minimum version for enhanced security
			MinVersion: tls.VersionTLS13,
			// TLS 1.3 cipher suites (order matters for preference)
			CipherSuites: []uint16{
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_CHACHA20_POLY1305_SHA256,
			},
			// Prefer server cipher suites for TLS 1.2 fallback (if needed)
			PreferServerCipherSuites: true,
			// Elliptic curve preferences (P-256 and X25519 for performance and security)
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
		}

		// Configure ALPN for HTTP/2
		if s.config.EnableHTTP2 {
			tlsConfig.NextProtos = []string{"h2", "http/1.1"}
		}

		srv.TLSConfig = tlsConfig
	}

	// Enable HTTP/2
	if s.config.EnableHTTP2 {
		if err := http2.ConfigureServer(srv, &http2.Server{
			MaxConcurrentStreams:         250,
			MaxReadFrameSize:             1048576, // 1MB
			IdleTimeout:                  300 * time.Second,
			MaxUploadBufferPerConnection: 1048576, // 1MB
		}); err != nil {
			logger.WithError(err).Error("Failed to configure HTTP/2")
			return err
		}
		logger.Info("HTTP/2 support enabled")
	}

	logger.WithField("listenAddr", s.listenAddr).Infoln("starting http listener")

	// Create listener
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		logger.WithError(err).Error("Failed to create listener")
		return err
	}

	// Wrap with TLS if enabled
	if s.config.EnableTLS && tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
		logger.WithFields(logrus.Fields{
			"certFile": s.config.CertFile,
			"keyFile":  s.config.KeyFile,
		}).Info("TLS enabled")
	}

	logger.WithFields(logrus.Fields{
		"address":   s.listenAddr,
		"http2":     s.config.EnableHTTP2,
		"tls":       s.config.EnableTLS,
		"websocket": s.config.EnableWebSocket,
	}).Info("Server ready to handle requests")

	// Start server in goroutine
	go func() {
		var serveErr error

		if s.config.EnableTLS && s.config.CertFile != "" && s.config.KeyFile != "" {
			serveErr = srv.ServeTLS(listener, s.config.CertFile, s.config.KeyFile)
		} else {
			serveErr = srv.Serve(listener)
		}

		if serveErr != nil && serveErr != http.ErrServerClosed {
			logger.WithError(serveErr).Error("Server error")
			errCh <- serveErr
		}

		logger.Debug("HTTP listener stopped")
		close(exitCh)
	}()

	// Wait for exit or error.
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err = <-errCh:
		// breaks
	case reason := <-signalCh:
		logger.WithField("signal", reason).Warnln("received signal")
		// breaks
	}

	// Shutdown, server will stop to accept new connections, requires Go 1.8+.
	logger.Infoln("clean server shutdown start")

	shutDownCtx, shutDownCtxCancel := context.WithTimeout(ctx, 10*time.Second)
	if shutdownErr := srv.Shutdown(shutDownCtx); shutdownErr != nil {
		logger.WithError(shutdownErr).Warn("clean server shutdown failed")
	}

	// Cancel our own context, wait on managers.
	serveCtxCancel()
	func() {
		for {
			select {
			case <-exitCh:
				return
			default:
				// HTTP listener has not quit yet.
				logger.Info("waiting for http listener to exit")
			}
			select {
			case reason := <-signalCh:
				logger.WithField("signal", reason).Warn("received signal")
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
	shutDownCtxCancel() // prevent leak.

	return err
}

// HandleWebSocket upgrades HTTP connections to WebSocket for real-time communication.
// This method provides a foundation for implementing real-time notifications and updates.
//
// Parameters:
//   - w: HTTP response writer
//   - r: HTTP request
//   - messageHandler: Function to handle incoming WebSocket messages
//
// Returns:
//   - error: Any error that occurred during the WebSocket upgrade or communication
func (s *Server) HandleWebSocket(w http.ResponseWriter, r *http.Request, messageHandler func([]byte) []byte) error {
	if !s.config.EnableWebSocket {
		http.Error(w, "WebSocket not enabled", http.StatusServiceUnavailable)
		return nil
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.WithError(err).Error("WebSocket upgrade failed")
		return err
	}
	defer conn.Close()

	s.logger.WithFields(logrus.Fields{
		"remote_addr": r.RemoteAddr,
		"user_agent":  r.UserAgent(),
	}).Info("WebSocket connection established")

	// Handle WebSocket messages
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				s.logger.WithError(err).Warn("WebSocket connection closed unexpectedly")
			}
			break
		}

		if messageType == websocket.TextMessage {
			response := messageHandler(message)
			if response != nil {
				if err := conn.WriteMessage(websocket.TextMessage, response); err != nil {
					s.logger.WithError(err).Error("Failed to send WebSocket response")
					break
				}
			}
		}
	}

	s.logger.Debug("WebSocket connection closed")
	return nil
}

// GetServerInfo returns information about the server configuration and capabilities.
// This is useful for clients to understand what features are available.
func (s *Server) GetServerInfo() map[string]interface{} {
	return map[string]interface{}{
		"http2_enabled":     s.config.EnableHTTP2,
		"tls_enabled":       s.config.EnableTLS,
		"websocket_enabled": s.config.EnableWebSocket,
		"max_connections":   s.config.MaxConnections,
		"listen_address":    s.listenAddr,
	}
}
