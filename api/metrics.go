package api

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// InitMetrics registers the Prometheus /metrics scrape endpoint when enabled
// is true. Driven by monitoring.enable_metrics — left unregistered (404) when
// false or unset, mirroring the deny-by-default posture of the rest of the API.
func (api *API) InitMetrics(enabled bool) {
	if !enabled {
		api.Logger.Infoln("Metrics endpoint disabled (monitoring.enable_metrics=false)")
		return
	}

	api.BaseRoutes.Metrics.Handle("/metrics", promhttp.Handler()).Methods(http.MethodGet)
	api.Logger.Infoln("Metrics API route initialized")
}
