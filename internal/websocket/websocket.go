// Package websocket provides real-time notification support via WebSocket connections.
package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"

	"password-manager/internal/logging"
)

// Message represents a WebSocket message.
type Message struct {
	Type      string                 `json:"type"`
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	UserID    string                 `json:"user_id,omitempty"`
}

// Client represents a WebSocket client connection.
type Client struct {
	ID       string
	UserID   string
	Conn     *websocket.Conn
	Send     chan *Message
	Hub      *Hub
	Logger   *logging.Logger
	ctx      context.Context
	cancel   context.CancelFunc
}

// Hub maintains active WebSocket connections and broadcasts messages.
type Hub struct {
	clients    map[string]*Client
	broadcast  chan *Message
	register   chan *Client
	unregister chan *Client
	logger     *logging.Logger
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewHub creates a new WebSocket hub.
func NewHub(logger *logging.Logger) *Hub {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &Hub{
		clients:    make(map[string]*Client),
		broadcast:  make(chan *Message, 100),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		logger:     logger,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start starts the WebSocket hub.
func (h *Hub) Start() {
	h.logger.Info("Starting WebSocket hub")
	go h.run()
}

// Stop stops the WebSocket hub.
func (h *Hub) Stop() {
	h.logger.Info("Stopping WebSocket hub")
	h.cancel()
	close(h.broadcast)
	close(h.register)
	close(h.unregister)
}

// run handles hub operations.
func (h *Hub) run() {
	ticker := time.NewTicker(54 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client.ID] = client
			h.mu.Unlock()
			
			h.logger.WithFields(logrus.Fields{
				"client_id": client.ID,
				"user_id":   client.UserID,
			}).Info("WebSocket client registered")
			
			// Send welcome message
			welcome := &Message{
				Type:      "connection",
				ID:        "welcome",
				Timestamp: time.Now(),
				Data: map[string]interface{}{
					"status":    "connected",
					"client_id": client.ID,
				},
			}
			
			select {
			case client.Send <- welcome:
			default:
				close(client.Send)
				h.mu.Lock()
				delete(h.clients, client.ID)
				h.mu.Unlock()
			}

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client.ID]; ok {
				delete(h.clients, client.ID)
				close(client.Send)
			}
			h.mu.Unlock()
			
			h.logger.WithFields(logrus.Fields{
				"client_id": client.ID,
				"user_id":   client.UserID,
			}).Info("WebSocket client unregistered")

		case message := <-h.broadcast:
			h.mu.RLock()
			for _, client := range h.clients {
				// Filter messages by user ID if specified
				if message.UserID != "" && message.UserID != client.UserID {
					continue
				}
				
				select {
				case client.Send <- message:
				default:
					close(client.Send)
					delete(h.clients, client.ID)
				}
			}
			h.mu.RUnlock()

		case <-ticker.C:
			// Send ping to all clients
			h.mu.RLock()
			for _, client := range h.clients {
				select {
				case client.Send <- &Message{
					Type:      "ping",
					ID:        "ping",
					Timestamp: time.Now(),
					Data:      map[string]interface{}{"ping": time.Now().Unix()},
				}:
				default:
					close(client.Send)
					delete(h.clients, client.ID)
				}
			}
			h.mu.RUnlock()

		case <-h.ctx.Done():
			h.logger.Info("WebSocket hub shutting down")
			return
		}
	}
}

// Broadcast sends a message to all connected clients.
func (h *Hub) Broadcast(message *Message) {
	select {
	case h.broadcast <- message:
	default:
		h.logger.Warn("WebSocket broadcast channel full, dropping message")
	}
}

// BroadcastToUser sends a message to a specific user.
func (h *Hub) BroadcastToUser(userID string, message *Message) {
	message.UserID = userID
	h.Broadcast(message)
}

// GetClientCount returns the number of connected clients.
func (h *Hub) GetClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// GetUserClients returns all clients for a specific user.
func (h *Hub) GetUserClients(userID string) []*Client {
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	var userClients []*Client
	for _, client := range h.clients {
		if client.UserID == userID {
			userClients = append(userClients, client)
		}
	}
	return userClients
}

// WebSocketUpgrader configures the WebSocket upgrader.
var WebSocketUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// In production, implement proper origin checking
		return true
	},
	Subprotocols: []string{"password-manager-v1"},
}

// HandleWebSocket handles WebSocket connection upgrades.
func (h *Hub) HandleWebSocket(w http.ResponseWriter, r *http.Request, userID string) {
	conn, err := WebSocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.WithError(err).Error("Failed to upgrade WebSocket connection")
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	client := &Client{
		ID:     generateClientID(),
		UserID: userID,
		Conn:   conn,
		Send:   make(chan *Message, 256),
		Hub:    h,
		Logger: h.logger,
		ctx:    ctx,
		cancel: cancel,
	}

	client.Hub.register <- client

	// Start goroutines for reading and writing
	go client.writePump()
	go client.readPump()
}

// readPump handles reading messages from the WebSocket connection.
func (c *Client) readPump() {
	defer func() {
		c.Hub.unregister <- c
		c.Conn.Close()
		c.cancel()
	}()

	c.Conn.SetReadLimit(512)
	c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			_, messageBytes, err := c.Conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					c.Logger.WithFields(logrus.Fields{
						"client_id": c.ID,
						"error":     err,
					}).Error("WebSocket read error")
				}
				break
			}

			var message Message
			if err := json.Unmarshal(messageBytes, &message); err != nil {
				c.Logger.WithFields(logrus.Fields{
					"client_id": c.ID,
					"error":     err,
				}).Error("Failed to unmarshal WebSocket message")
				continue
			}

			// Handle client messages (e.g., subscription management)
			c.handleClientMessage(&message)
		}
	}
}

// writePump handles writing messages to the WebSocket connection.
func (c *Client) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
		c.cancel()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.Conn.WriteJSON(message); err != nil {
				c.Logger.WithFields(logrus.Fields{
					"client_id": c.ID,
					"error":     err,
				}).Error("WebSocket write error")
				return
			}

		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}

		case <-c.ctx.Done():
			return
		}
	}
}

// handleClientMessage processes messages from clients.
func (c *Client) handleClientMessage(message *Message) {
	c.Logger.WithFields(logrus.Fields{
		"client_id":    c.ID,
		"message_type": message.Type,
	}).Debug("Received client message")

	switch message.Type {
	case "subscribe":
		// Handle subscription to specific events
		c.handleSubscription(message)
	case "unsubscribe":
		// Handle unsubscription from events
		c.handleUnsubscription(message)
	case "pong":
		// Handle pong response
		c.Logger.Debug("Received pong from client")
	default:
		c.Logger.WithField("message_type", message.Type).Warn("Unknown message type from client")
	}
}

// handleSubscription handles client subscription requests.
func (c *Client) handleSubscription(message *Message) {
	if eventType, ok := message.Data["event_type"].(string); ok {
		c.Logger.WithFields(logrus.Fields{
			"client_id":  c.ID,
			"event_type": eventType,
		}).Info("Client subscribed to event type")

		// Send confirmation
		response := &Message{
			Type:      "subscription_confirmed",
			ID:        message.ID,
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"event_type": eventType,
				"status":     "subscribed",
			},
		}

		select {
		case c.Send <- response:
		default:
			c.Logger.Warn("Failed to send subscription confirmation")
		}
	}
}

// handleUnsubscription handles client unsubscription requests.
func (c *Client) handleUnsubscription(message *Message) {
	if eventType, ok := message.Data["event_type"].(string); ok {
		c.Logger.WithFields(logrus.Fields{
			"client_id":  c.ID,
			"event_type": eventType,
		}).Info("Client unsubscribed from event type")

		// Send confirmation
		response := &Message{
			Type:      "unsubscription_confirmed",
			ID:        message.ID,
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"event_type": eventType,
				"status":     "unsubscribed",
			},
		}

		select {
		case c.Send <- response:
		default:
			c.Logger.Warn("Failed to send unsubscription confirmation")
		}
	}
}

// generateClientID generates a unique client ID.
func generateClientID() string {
	return "ws_" + time.Now().Format("20060102150405") + "_" + generateRandomString(8)
}

// generateRandomString generates a random string of specified length.
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

// NotificationService provides methods to send real-time notifications.
type NotificationService struct {
	hub    *Hub
	logger *logging.Logger
}

// NewNotificationService creates a new notification service.
func NewNotificationService(hub *Hub, logger *logging.Logger) *NotificationService {
	return &NotificationService{
		hub:    hub,
		logger: logger,
	}
}

// SendSecretExpirationAlert sends a secret expiration alert.
func (ns *NotificationService) SendSecretExpirationAlert(userID, secretName string, expiresAt time.Time) {
	message := &Message{
		Type:      "secret_expiration",
		ID:        "exp_" + time.Now().Format("20060102150405"),
		Timestamp: time.Now(),
		UserID:    userID,
		Data: map[string]interface{}{
			"secret_name": secretName,
			"expires_at":  expiresAt.Format(time.RFC3339),
			"message":     "Secret '" + secretName + "' will expire soon",
		},
	}

	ns.hub.BroadcastToUser(userID, message)
}

// SendSystemHealthUpdate sends a system health status update.
func (ns *NotificationService) SendSystemHealthUpdate(status string, details map[string]interface{}) {
	message := &Message{
		Type:      "system_health",
		ID:        "health_" + time.Now().Format("20060102150405"),
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"status":  status,
			"details": details,
		},
	}

	ns.hub.Broadcast(message)
}

// SendAuditLogStream sends audit log entries in real-time.
func (ns *NotificationService) SendAuditLogStream(userID, operation, status, details string) {
	message := &Message{
		Type:      "audit_log",
		ID:        "audit_" + time.Now().Format("20060102150405"),
		Timestamp: time.Now(),
		UserID:    userID,
		Data: map[string]interface{}{
			"operation": operation,
			"status":    status,
			"details":   details,
		},
	}

	ns.hub.BroadcastToUser(userID, message)
}

// AuthenticateWebSocket performs authentication for WebSocket connections.
func AuthenticateWebSocket(r *http.Request) (string, error) {
	// Try to get token from query parameter
	token := r.URL.Query().Get("token")
	if token == "" {
		// Try to get from Authorization header
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	if token == "" {
		return "", fmt.Errorf("no authentication token provided")
	}

	// For now, return a simple validation - this should integrate with your existing auth
	// In a complete implementation, this would call the actual JWT validation
	if len(token) < 10 {
		return "", fmt.Errorf("invalid token format")
	}

	// Extract user ID from token - this is a placeholder
	// In production, parse the JWT and extract the user ID
	return "websocket_user", nil
}