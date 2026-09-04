package cliclient

import (
	"errors"
	"fmt"

	"rocketvault/internal/vaultapi"
)

// CLIError turns a vaultapi error into text phrased for a CLI user. vaultapi's
// own Hint is written for an operator reading a server log; a person at a
// terminal needs to know which flag to reach for instead.
//
// The wording mirrors secretsAPIError (secrets.go:29-48), which the secrets
// adapters have used since they shipped, so the two paths read alike until
// those adapters move onto this one.
//
// Any error that is not a *vaultapi.APIError passes through with op for
// context -- transport failures already read clearly. errors.As rather than a
// type assertion, so a wrapped APIError is still classified.
func CLIError(op string, err error) error {
	if err == nil {
		return nil
	}

	var apiErr *vaultapi.APIError
	if !errors.As(err, &apiErr) {
		return fmt.Errorf("failed to %s: %w", op, err)
	}

	switch apiErr.Kind {
	case vaultapi.KindUnauthorized:
		return fmt.Errorf(
			"failed to %s: the session token was rejected; re-run with --username/--password/--totp-code to re-authenticate, or run 'rocketvault users login'", op)
	case vaultapi.KindForbidden:
		return fmt.Errorf(
			"failed to %s: no role assignment in this vault grants the required action", op)
	case vaultapi.KindNotFound:
		return fmt.Errorf("failed to %s: not found", op)
	case vaultapi.KindConflict:
		return fmt.Errorf("failed to %s: it already exists", op)
	case vaultapi.KindServer:
		return fmt.Errorf("failed to %s: the server returned an error (HTTP %d)", op, apiErr.StatusCode)
	default:
		return fmt.Errorf("failed to %s: %w", op, err)
	}
}
