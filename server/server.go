package server

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
)

// Server represents the HTTP server for the vault service application.
// It contains the router for handling HTTP requests, the HTTP server instance,
// the address on which the server listens, and a logger for logging server activities.
type Server struct {
	Router     *mux.Router
	Server     *http.Server
	listenAddr string
	logger     logrus.FieldLogger
}

// NewServer creates a new instance of Server with the provided logger and listen address.
// It initializes the Router using mux.NewRouter().
//
// Parameters:
//   - logger: an instance of logrus.FieldLogger for logging purposes.
//   - listenAddr: a string representing the address on which the server will listen.
//
// Returns:
//   - A pointer to a newly created Server instance.
func NewServer(logger logrus.FieldLogger, listenAddr string) *Server {
	return &Server{
		Router:     mux.NewRouter(),
		logger:     logger,
		listenAddr: listenAddr,
	}
}

// StartServer starts the HTTP server and listens for incoming requests.
// It sets up signal handling for graceful shutdown and manages server lifecycle.
//
// Parameters:
//   - ctx: The context to control server lifecycle.
//
// Returns:
//   - error: An error if the server fails to start or encounters an issue during runtime.
//
// The server listens on the address specified in the Server struct's listenAddr field.
// It uses a CORS middleware to allow all origins. The server has configured timeouts for
// write, read, and idle connections.
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

	cc := cors.AllowAll()
	// HTTP listener.
	srv := &http.Server{
		Handler:      cc.Handler(s.Router),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	logger.WithField("listenAddr", s.listenAddr).Infoln("starting http listener")

	// TODO: Also support unix socket.
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	logger.Infoln("ready to handle requests")

	go func() {
		serveErr := srv.Serve(listener)
		if serveErr != nil {
			errCh <- serveErr
		}

		logger.Debugln("http listener stopped")
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
