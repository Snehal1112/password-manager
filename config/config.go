package config

import (
	"net"
	"net/http"

	"github.com/sirupsen/logrus"
)

// Config holds the configuration settings for the vault service application.
// It includes settings for the server's listening address, logging, HTTP transport,
// and trusted proxy IPs and networks.
type Config struct {
	// ListenAddr is the address on which the server will listen for incoming requests.
	ListenAddr string

	// Logger is the logger used for logging messages.
	Logger logrus.FieldLogger

	// HTTPTransport is the transport used for making HTTP requests.
	HTTPTransport http.RoundTripper

	// TrustedProxyIPs is a list of IP addresses that are considered trusted proxies.
	TrustedProxyIPs []*net.IP

	// TrustedProxyNets is a list of IP networks that are considered trusted proxies.
	TrustedProxyNets []*net.IPNet
}
