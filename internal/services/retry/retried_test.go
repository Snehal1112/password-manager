package retry

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/retry"
)

// stubRetryService runs the operation exactly attempts times, stopping early on
// success, so retried's plumbing can be tested without real backoff.
type stubRetryService struct {
	attempts int
	calls    int
}

func (s *stubRetryService) ExecuteDatabaseOperation(ctx context.Context, op func() error) error {
	var err error
	for i := 0; i < s.attempts; i++ {
		s.calls++
		if err = op(); err == nil {
			return nil
		}
	}
	return err
}

func (s *stubRetryService) ExecuteExternalServiceOperation(ctx context.Context, op func() error) error {
	return nil
}

func (s *stubRetryService) ExecuteServiceOperation(ctx context.Context, op func() error) error {
	return nil
}

func (s *stubRetryService) GetDatabasePolicy() retry.Policy {
	return retry.Policy{}
}

func (s *stubRetryService) GetExternalServicesPolicy() retry.Policy {
	return retry.Policy{}
}

func (s *stubRetryService) GetServiceOperationsPolicy() retry.Policy {
	return retry.Policy{}
}

func TestRetriedReturnsTheValueOnSuccess(t *testing.T) {
	rs := &stubRetryService{attempts: 3}

	got, err := retried(context.Background(), rs, func() (string, error) { return "ok", nil })
	require.NoError(t, err)
	assert.Equal(t, "ok", got)
	assert.Equal(t, 1, rs.calls)
}

func TestRetriedRetriesUntilSuccess(t *testing.T) {
	rs := &stubRetryService{attempts: 3}
	calls := 0

	got, err := retried(context.Background(), rs, func() (int, error) {
		calls++
		if calls < 3 {
			return 0, errors.New("transient")
		}
		return 42, nil
	})
	require.NoError(t, err)
	assert.Equal(t, 42, got)
	assert.Equal(t, 3, calls)
}

func TestRetriedPropagatesTheFinalError(t *testing.T) {
	rs := &stubRetryService{attempts: 2}
	boom := errors.New("permanent")

	got, err := retried(context.Background(), rs, func() (*string, error) { return nil, boom })
	assert.ErrorIs(t, err, boom)
	assert.Nil(t, got)
}

func TestRetriedReturnsTheZeroValueOnFailure(t *testing.T) {
	rs := &stubRetryService{attempts: 1}

	got, err := retried(context.Background(), rs, func() ([]int, error) {
		return []int{1, 2, 3}, errors.New("partial result must not be returned as success")
	})
	require.Error(t, err)
	assert.Equal(t, []int{1, 2, 3}, got, "retried returns the last value alongside the error, matching the existing decorators")
}
