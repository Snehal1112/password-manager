package retry

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

"password-manager/internal/webhooks"
)

// RetryWebhookService extends the standard webhook service with retry capabilities
type RetryWebhookService interface {
	// Standard webhook operations
	RegisterEndpoint(endpoint *webhooks.WebhookEndpoint)
	UnregisterEndpoint(endpointID string)
	TriggerEvent(event *webhooks.WebhookEvent)
	GetEndpoint(endpointID string) (*webhooks.WebhookEndpoint, bool)
	ListEndpoints() []*webhooks.WebhookEndpoint

	// Retry-specific operations
	DeliverWebhookWithRetry(ctx context.Context, job *webhooks.DeliveryJob) *webhooks.WebhookDelivery
}

// retryWebhookService implements RetryWebhookService with retry logic
type retryWebhookService struct {
	baseManager  *webhooks.WebhookManager
	retryService RetryService
	logger       *logrus.Logger
	httpClient   *http.Client
}

// NewRetryWebhookService creates a new retry-aware webhook service
func NewRetryWebhookService(baseManager *webhooks.WebhookManager, retryService RetryService, logger *logrus.Logger) RetryWebhookService {
	return &retryWebhookService{
		baseManager:  baseManager,
		retryService: retryService,
		logger:       logger,
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

// RegisterEndpoint registers a webhook endpoint
func (s *retryWebhookService) RegisterEndpoint(endpoint *webhooks.WebhookEndpoint) {
	s.baseManager.RegisterEndpoint(endpoint)
}

// UnregisterEndpoint unregisters a webhook endpoint
func (s *retryWebhookService) UnregisterEndpoint(endpointID string) {
	s.baseManager.UnregisterEndpoint(endpointID)
}

// TriggerEvent triggers a webhook event
func (s *retryWebhookService) TriggerEvent(event *webhooks.WebhookEvent) {
	s.baseManager.TriggerEvent(event)
}

// GetEndpoint gets a webhook endpoint
func (s *retryWebhookService) GetEndpoint(endpointID string) (*webhooks.WebhookEndpoint, bool) {
	return s.baseManager.GetEndpoint(endpointID)
}

// ListEndpoints lists all webhook endpoints
func (s *retryWebhookService) ListEndpoints() []*webhooks.WebhookEndpoint {
	return s.baseManager.ListEndpoints()
}

// DeliverWebhookWithRetry delivers a webhook with comprehensive retry logic
func (s *retryWebhookService) DeliverWebhookWithRetry(ctx context.Context, job *webhooks.DeliveryJob) *webhooks.WebhookDelivery {
	delivery := &webhooks.WebhookDelivery{
		ID:            generateDeliveryID(),
		WebhookID:     job.Endpoint.ID,
		EventID:       job.Event.ID,
		URL:           job.Endpoint.URL,
		AttemptNumber: job.Attempt,
		DeliveredAt:   time.Now(),
	}

	start := time.Now()

	// Execute webhook delivery with retry logic
	err := s.retryService.ExecuteExternalServiceOperation(ctx, func() error {
		return s.performWebhookDelivery(job, delivery)
	})

	if err != nil {
		delivery.Error = fmt.Sprintf("Webhook delivery failed after retries: %v", err)
		delivery.Success = false
	} else {
		delivery.Success = true
	}

	delivery.Duration = time.Since(start)

	s.logger.WithFields(logrus.Fields{
		"delivery_id": delivery.ID,
		"endpoint_id": job.Endpoint.ID,
		"event_id":    job.Event.ID,
		"http_status": delivery.HTTPStatus,
		"duration_ms": delivery.Duration.Milliseconds(),
		"success":     delivery.Success,
		"attempt":     job.Attempt,
	}).Info("Webhook delivered with retry")

	return delivery
}

// performWebhookDelivery performs the actual webhook delivery
func (s *retryWebhookService) performWebhookDelivery(job *webhooks.DeliveryJob, delivery *webhooks.WebhookDelivery) error {
	// Prepare request body
	eventData := map[string]interface{}{
		"id":        job.Event.ID,
		"type":      job.Event.Type,
		"timestamp": job.Event.Timestamp,
		"data":      job.Event.Data,
		"user_id":   job.Event.UserID,
		"source":    job.Event.Source,
	}

	requestBody, err := json.Marshal(eventData)
	if err != nil {
		return fmt.Errorf("failed to marshal event data: %w", err)
	}

	// Create request
	req, err := http.NewRequest("POST", job.Endpoint.URL, bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "PasswordManager-Webhook/1.0")

	// Add custom headers from endpoint configuration
	for key, value := range job.Endpoint.Headers {
		req.Header.Set(key, value)
	}

	// Generate signature if secret is provided
	if job.Endpoint.Secret != "" {
		signature := s.generateSignature(requestBody, job.Endpoint.Secret)
		req.Header.Set("X-Webhook-Signature", signature)
	}

	// Capture request headers
	reqHeaders, _ := json.Marshal(req.Header)
	delivery.RequestHeaders = string(reqHeaders)

	// Perform request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	delivery.HTTPStatus = resp.StatusCode

	// Read response body (limited size)
	responseBody := make([]byte, 1024)
	n, _ := resp.Body.Read(responseBody)
	delivery.ResponseBody = string(responseBody[:n])

	// Capture response headers
	respHeaders, _ := json.Marshal(resp.Header)
	delivery.ResponseHeaders = string(respHeaders)

	// Check if delivery was successful
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned non-success status: %d", resp.StatusCode)
	}

	return nil
}

// generateSignature generates HMAC signature for webhook payload
func (s *retryWebhookService) generateSignature(payload []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// generateDeliveryID generates a unique delivery ID
func generateDeliveryID() string {
	return fmt.Sprintf("delivery_%d", time.Now().UnixNano())
}

// RetryWebhookDeliveryJob represents a webhook delivery job with retry support
type RetryWebhookDeliveryJob struct {
	*webhooks.DeliveryJob
	MaxRetries int
	RetryDelay time.Duration
}

// NewRetryWebhookDeliveryJob creates a new retry webhook delivery job
func NewRetryWebhookDeliveryJob(job *webhooks.DeliveryJob, maxRetries int, retryDelay time.Duration) *RetryWebhookDeliveryJob {
	return &RetryWebhookDeliveryJob{
		DeliveryJob: job,
		MaxRetries:  maxRetries,
		RetryDelay:  retryDelay,
	}
}