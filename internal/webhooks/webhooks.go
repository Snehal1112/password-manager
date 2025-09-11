// Package webhooks provides webhook functionality with retry policies and dead letter queues.
package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"password-manager/internal/logging"
)

// WebhookEvent represents a webhook event.
type WebhookEvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	UserID    string                 `json:"user_id,omitempty"`
	Source    string                 `json:"source"`
}

// WebhookEndpoint represents a webhook endpoint configuration.
type WebhookEndpoint struct {
	ID          string            `json:"id"`
	URL         string            `json:"url"`
	Secret      string            `json:"secret"`
	Events      []string          `json:"events"`
	Active      bool              `json:"active"`
	Headers     map[string]string `json:"headers"`
	MaxRetries  int               `json:"max_retries"`
	RetryDelay  time.Duration     `json:"retry_delay"`
	Timeout     time.Duration     `json:"timeout"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// WebhookDelivery represents a webhook delivery attempt.
type WebhookDelivery struct {
	ID              string        `json:"id"`
	WebhookID       string        `json:"webhook_id"`
	EventID         string        `json:"event_id"`
	URL             string        `json:"url"`
	HTTPStatus      int           `json:"http_status"`
	ResponseBody    string        `json:"response_body"`
	ResponseHeaders string        `json:"response_headers"`
	RequestBody     string        `json:"request_body"`
	RequestHeaders  string        `json:"request_headers"`
	AttemptNumber   int           `json:"attempt_number"`
	Duration        time.Duration `json:"duration"`
	Error           string        `json:"error,omitempty"`
	DeliveredAt     time.Time     `json:"delivered_at"`
	Success         bool          `json:"success"`
}

// WebhookManager manages webhook endpoints and deliveries.
type WebhookManager struct {
	endpoints     map[string]*WebhookEndpoint
	deliveryQueue chan *DeliveryJob
	deadLetterQ   chan *DeliveryJob
	logger        *logging.Logger
	httpClient    *http.Client
	workers       int
	ctx           context.Context
	cancel        context.CancelFunc
}

// DeliveryJob represents a webhook delivery job.
type DeliveryJob struct {
	Endpoint *WebhookEndpoint
	Event    *WebhookEvent
	Attempt  int
	MaxRetry int
}

// NewWebhookManager creates a new webhook manager.
func NewWebhookManager(logger *logging.Logger, workers int) *WebhookManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &WebhookManager{
		endpoints:     make(map[string]*WebhookEndpoint),
		deliveryQueue: make(chan *DeliveryJob, 1000),
		deadLetterQ:   make(chan *DeliveryJob, 100),
		logger:        logger,
		workers:       workers,
		ctx:           ctx,
		cancel:        cancel,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// Start starts the webhook delivery workers.
func (wm *WebhookManager) Start() {
	wm.logger.WithField("workers", wm.workers).Info("Starting webhook delivery workers")
	
	for i := 0; i < wm.workers; i++ {
		go wm.deliveryWorker(i)
	}
	
	// Start dead letter queue processor
	go wm.deadLetterProcessor()
}

// Stop stops the webhook manager.
func (wm *WebhookManager) Stop() {
	wm.logger.Info("Stopping webhook manager")
	wm.cancel()
	close(wm.deliveryQueue)
	close(wm.deadLetterQ)
}

// RegisterEndpoint registers a webhook endpoint.
func (wm *WebhookManager) RegisterEndpoint(endpoint *WebhookEndpoint) {
	if endpoint.MaxRetries == 0 {
		endpoint.MaxRetries = 3
	}
	if endpoint.RetryDelay == 0 {
		endpoint.RetryDelay = 5 * time.Second
	}
	if endpoint.Timeout == 0 {
		endpoint.Timeout = 30 * time.Second
	}
	if endpoint.Headers == nil {
		endpoint.Headers = make(map[string]string)
	}
	
	endpoint.CreatedAt = time.Now()
	endpoint.UpdatedAt = time.Now()
	
	wm.endpoints[endpoint.ID] = endpoint
	
	wm.logger.WithFields(logrus.Fields{
		"endpoint_id": endpoint.ID,
		"url":         endpoint.URL,
		"events":      endpoint.Events,
	}).Info("Webhook endpoint registered")
}

// UnregisterEndpoint removes a webhook endpoint.
func (wm *WebhookManager) UnregisterEndpoint(endpointID string) {
	delete(wm.endpoints, endpointID)
	wm.logger.WithField("endpoint_id", endpointID).Info("Webhook endpoint unregistered")
}

// GetEndpoint retrieves a webhook endpoint.
func (wm *WebhookManager) GetEndpoint(endpointID string) (*WebhookEndpoint, bool) {
	endpoint, exists := wm.endpoints[endpointID]
	return endpoint, exists
}

// ListEndpoints returns all webhook endpoints.
func (wm *WebhookManager) ListEndpoints() []*WebhookEndpoint {
	endpoints := make([]*WebhookEndpoint, 0, len(wm.endpoints))
	for _, endpoint := range wm.endpoints {
		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

// TriggerEvent triggers a webhook event to all matching endpoints.
func (wm *WebhookManager) TriggerEvent(event *WebhookEvent) {
	wm.logger.WithFields(logrus.Fields{
		"event_id":   event.ID,
		"event_type": event.Type,
		"user_id":    event.UserID,
	}).Info("Triggering webhook event")
	
	for _, endpoint := range wm.endpoints {
		if !endpoint.Active {
			continue
		}
		
		// Check if endpoint is subscribed to this event type
		subscribed := false
		for _, eventType := range endpoint.Events {
			if eventType == event.Type || eventType == "*" {
				subscribed = true
				break
			}
		}
		
		if !subscribed {
			continue
		}
		
		// Queue delivery job
		job := &DeliveryJob{
			Endpoint: endpoint,
			Event:    event,
			Attempt:  1,
			MaxRetry: endpoint.MaxRetries,
		}
		
		select {
		case wm.deliveryQueue <- job:
			wm.logger.WithFields(logrus.Fields{
				"endpoint_id": endpoint.ID,
				"event_id":    event.ID,
			}).Debug("Webhook delivery job queued")
		default:
			wm.logger.WithFields(logrus.Fields{
				"endpoint_id": endpoint.ID,
				"event_id":    event.ID,
			}).Warn("Webhook delivery queue full, dropping job")
		}
	}
}

// deliveryWorker processes webhook delivery jobs.
func (wm *WebhookManager) deliveryWorker(workerID int) {
	logger := wm.logger.WithField("worker_id", workerID)
	logger.Info("Starting webhook delivery worker")
	
	for {
		select {
		case job, ok := <-wm.deliveryQueue:
			if !ok {
				logger.Info("Delivery queue closed, stopping worker")
				return
			}
			
			delivery := wm.deliverWebhook(job)
			
			if !delivery.Success && job.Attempt < job.MaxRetry {
				// Retry with exponential backoff
				job.Attempt++
				retryDelay := time.Duration(job.Attempt) * job.Endpoint.RetryDelay
				
				go func(job *DeliveryJob, delay time.Duration) {
					time.Sleep(delay)
					select {
					case wm.deliveryQueue <- job:
						logger.WithFields(logrus.Fields{
							"endpoint_id": job.Endpoint.ID,
							"event_id":    job.Event.ID,
							"attempt":     job.Attempt,
						}).Info("Webhook delivery job retried")
					case <-wm.ctx.Done():
						return
					}
				}(job, retryDelay)
			} else if !delivery.Success {
				// Send to dead letter queue
				select {
				case wm.deadLetterQ <- job:
					logger.WithFields(logrus.Fields{
						"endpoint_id": job.Endpoint.ID,
						"event_id":    job.Event.ID,
					}).Warn("Webhook delivery failed, sent to dead letter queue")
				default:
					logger.WithFields(logrus.Fields{
						"endpoint_id": job.Endpoint.ID,
						"event_id":    job.Event.ID,
					}).Error("Dead letter queue full, dropping failed delivery")
				}
			}
			
		case <-wm.ctx.Done():
			logger.Info("Context cancelled, stopping worker")
			return
		}
	}
}

// deliverWebhook performs the actual webhook delivery.
func (wm *WebhookManager) deliverWebhook(job *DeliveryJob) *WebhookDelivery {
	start := time.Now()
	
	delivery := &WebhookDelivery{
		ID:            fmt.Sprintf("del_%d_%s", time.Now().Unix(), job.Event.ID),
		WebhookID:     job.Endpoint.ID,
		EventID:       job.Event.ID,
		URL:           job.Endpoint.URL,
		AttemptNumber: job.Attempt,
		DeliveredAt:   time.Now(),
	}
	
	// Prepare request body
	requestBody, err := json.Marshal(job.Event)
	if err != nil {
		delivery.Error = fmt.Sprintf("Failed to marshal event: %v", err)
		delivery.Duration = time.Since(start)
		return delivery
	}
	
	delivery.RequestBody = string(requestBody)
	
	// Create HTTP request
	req, err := http.NewRequestWithContext(wm.ctx, "POST", job.Endpoint.URL, bytes.NewBuffer(requestBody))
	if err != nil {
		delivery.Error = fmt.Sprintf("Failed to create request: %v", err)
		delivery.Duration = time.Since(start)
		return delivery
	}
	
	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Password-Manager-Webhook/1.0")
	req.Header.Set("X-Event-Type", job.Event.Type)
	req.Header.Set("X-Event-ID", job.Event.ID)
	req.Header.Set("X-Delivery-ID", delivery.ID)
	
	// Add custom headers
	for key, value := range job.Endpoint.Headers {
		req.Header.Set(key, value)
	}
	
	// Generate signature if secret is provided
	if job.Endpoint.Secret != "" {
		signature := wm.generateSignature(requestBody, job.Endpoint.Secret)
		req.Header.Set("X-Webhook-Signature", signature)
	}
	
	// Capture request headers
	reqHeaders, _ := json.Marshal(req.Header)
	delivery.RequestHeaders = string(reqHeaders)
	
	// Perform request with timeout
	client := &http.Client{Timeout: job.Endpoint.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		delivery.Error = fmt.Sprintf("Request failed: %v", err)
		delivery.Duration = time.Since(start)
		return delivery
	}
	defer resp.Body.Close()
	
	delivery.HTTPStatus = resp.StatusCode
	delivery.Duration = time.Since(start)
	
	// Read response
	responseBody := make([]byte, 1024) // Limit response body size
	n, _ := resp.Body.Read(responseBody)
	delivery.ResponseBody = string(responseBody[:n])
	
	// Capture response headers
	respHeaders, _ := json.Marshal(resp.Header)
	delivery.ResponseHeaders = string(respHeaders)
	
	// Check if delivery was successful (2xx status codes)
	delivery.Success = resp.StatusCode >= 200 && resp.StatusCode < 300
	
	wm.logger.WithFields(logrus.Fields{
		"delivery_id":  delivery.ID,
		"endpoint_id":  job.Endpoint.ID,
		"event_id":     job.Event.ID,
		"http_status":  delivery.HTTPStatus,
		"duration_ms":  delivery.Duration.Milliseconds(),
		"success":      delivery.Success,
		"attempt":      job.Attempt,
	}).Info("Webhook delivered")
	
	return delivery
}

// generateSignature generates HMAC-SHA256 signature for webhook payload.
func (wm *WebhookManager) generateSignature(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// deadLetterProcessor handles failed webhook deliveries.
func (wm *WebhookManager) deadLetterProcessor() {
	wm.logger.Info("Starting dead letter queue processor")
	
	for {
		select {
		case job, ok := <-wm.deadLetterQ:
			if !ok {
				wm.logger.Info("Dead letter queue closed")
				return
			}
			
			wm.logger.WithFields(logrus.Fields{
				"endpoint_id": job.Endpoint.ID,
				"event_id":    job.Event.ID,
				"attempts":    job.Attempt,
			}).Error("Webhook delivery permanently failed")
			
			// Here you could implement additional handling:
			// - Store failed deliveries in database
			// - Send alerts to administrators
			// - Disable problematic endpoints
			
		case <-wm.ctx.Done():
			wm.logger.Info("Dead letter processor stopping")
			return
		}
	}
}

// ValidateSignature validates a webhook signature.
func ValidateSignature(payload []byte, signature, secret string) bool {
	if signature == "" || secret == "" {
		return false
	}
	
	expectedSig := "sha256=" + hex.EncodeToString(hmac.New(sha256.New, []byte(secret)).Sum(payload))
	return hmac.Equal([]byte(signature), []byte(expectedSig))
}