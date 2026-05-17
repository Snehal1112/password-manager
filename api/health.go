/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package api

import (
	"encoding/json"
	"net/http"

	"rocketvault/internal/health"
	"rocketvault/internal/logging"
)

// InitHealth registers health check routes.
func (api *API) InitHealth() {
	r := api.BaseRoutes.Health
	r.Handle("/ready", ApiHandler(api.App, func(c *Context, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})).Methods("GET")
	r.Handle("/live", ApiHandler(api.App, func(c *Context, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})).Methods("GET")
	r.Handle("", ApiHandler(api.App, func(c *Context, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})).Methods("GET")
}

// HealthHandler handles health check endpoints
type HealthHandler struct {
	collector *health.HealthCollector
	logger    *logging.Logger
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(collector *health.HealthCollector, logger *logging.Logger) *HealthHandler {
	return &HealthHandler{
		collector: collector,
		logger:    logger,
	}
}

// HealthCheck handles GET /health endpoint
func (h *HealthHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metrics, err := h.collector.CollectMetrics(r.Context())
	if err != nil {
		h.logger.LogAuditError("", "health_api", "failed", "Failed to collect health metrics", err)
		http.Error(w, "Failed to collect health metrics", http.StatusInternalServerError)
		return
	}

	queryMetrics := h.collector.GetQueryMetrics()

	// Create response struct without mutex
	response := struct {
		*health.HealthMetrics
		QueryMetrics struct {
			QueryCount    int64  `json:"query_count"`
			TotalDuration string `json:"total_duration"`
			AvgDuration   string `json:"avg_duration"`
			SlowQueries   int64  `json:"slow_queries"`
		} `json:"query_metrics"`
	}{
		HealthMetrics: metrics,
		QueryMetrics: struct {
			QueryCount    int64  `json:"query_count"`
			TotalDuration string `json:"total_duration"`
			AvgDuration   string `json:"avg_duration"`
			SlowQueries   int64  `json:"slow_queries"`
		}{
			QueryCount:    queryMetrics.QueryCount,
			TotalDuration: health.FormatDuration(queryMetrics.TotalDuration),
			AvgDuration:   health.FormatDuration(queryMetrics.AvgDuration),
			SlowQueries:   queryMetrics.SlowQueries,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.LogAuditError("", "health_api", "failed", "Failed to encode health metrics", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	h.logger.LogAuditInfo("", "health_api", "success", "Health metrics served via API")
}

// ReadinessCheck handles GET /health/ready endpoint
func (h *HealthHandler) ReadinessCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Basic readiness check - if we can collect metrics, we're ready
	_, err := h.collector.CollectMetrics(r.Context())
	if err != nil {
		h.logger.LogAuditError("", "readiness_api", "failed", "System not ready", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "not ready",
			"error":  err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ready",
	})

	h.logger.LogAuditInfo("", "readiness_api", "success", "Readiness check passed")
}

// LivenessCheck handles GET /health/live endpoint
func (h *HealthHandler) LivenessCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Simple liveness check - if the handler is responding, we're alive
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "alive",
	})

	h.logger.LogAuditInfo("", "liveness_api", "success", "Liveness check passed")
}
