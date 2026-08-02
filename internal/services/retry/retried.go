package retry

import "context"

// retried runs a value-returning operation under the retry policy, removing the
// var/closure/return boilerplate repeated across every decorator method. The
// last observed value is returned alongside any error, matching the behaviour
// of the hand-written decorators it replaces.
func retried[T any](ctx context.Context, rs RetryService, op func() (T, error)) (T, error) {
	var result T
	var opErr error

	retryErr := rs.ExecuteDatabaseOperation(ctx, func() error {
		result, opErr = op()
		return opErr
	})

	return result, retryErr
}
