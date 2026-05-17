package model

import (
	"time"

	"github.com/google/uuid"
)

// NewId returns a new random UUID string.
func NewId() string {
	return uuid.New().String()
}

// GetMillis returns the current time in milliseconds since Unix epoch.
func GetMillis() int64 {
	return time.Now().UnixMilli()
}
