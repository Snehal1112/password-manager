package retry

import (
	"testing"
)

func TestIsRetryableStatus(t *testing.T) {
	policy := Policy{
		RetryableStatuses: []int{500, 502, 503, 504},
	}

	tests := []struct {
		statusCode int
		expected   bool
	}{
		{200, false},
		{404, false},
		{500, true},
		{502, true},
		{503, true},
		{504, true},
		{505, false},
	}

	for _, tt := range tests {
		result := IsRetryableStatus(tt.statusCode, policy)
		if result != tt.expected {
			t.Errorf("IsRetryableStatus(%d) = %v, want %v", tt.statusCode, result, tt.expected)
		}
	}
}

func TestPolicyConfiguration(t *testing.T) {
	policy := Policy{
		Enabled:           true,
		MaxAttempts:       3,
		InitialDelay:      10,
		MaxDelay:          100,
		BackoffMultiplier: 2.0,
		JitterEnabled:     false,
		RetryableStatuses: []int{500, 502, 503, 504},
	}

	if !policy.Enabled {
		t.Error("policy should be enabled")
	}

	if policy.MaxAttempts != 3 {
		t.Errorf("expected max attempts 3, got %d", policy.MaxAttempts)
	}

	if !IsRetryableStatus(500, policy) {
		t.Error("status 500 should be retryable")
	}

	if IsRetryableStatus(200, policy) {
		t.Error("status 200 should not be retryable")
	}
}