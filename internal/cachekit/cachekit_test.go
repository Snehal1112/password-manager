package cachekit_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"rocketvault/internal/cachekit"
)

func TestConfig_Validate_Valid(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: 10 * time.Second, MaxEntries: 100}
	assert.NoError(t, cfg.Validate())
}

func TestConfig_Validate_TTLNotPositive(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: 0, CleanupInterval: time.Second, MaxEntries: 100}
	assert.Error(t, cfg.Validate())
}

func TestConfig_Validate_CleanupIntervalNotPositive(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: 0, MaxEntries: 100}
	assert.Error(t, cfg.Validate())
}

func TestConfig_Validate_CleanupIntervalNotLessThanTTL(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Minute, MaxEntries: 100}
	assert.Error(t, cfg.Validate())
}

func TestConfig_Validate_MaxEntriesNegative(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: -1}
	assert.Error(t, cfg.Validate())
}

func TestConfig_Validate_MaxEntriesZeroIsValid(t *testing.T) {
	cfg := cachekit.Config{Enabled: true, TTL: time.Minute, CleanupInterval: time.Second, MaxEntries: 0}
	assert.NoError(t, cfg.Validate(), "0 means unbounded, not invalid")
}
