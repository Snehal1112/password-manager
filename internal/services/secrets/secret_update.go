package secrets

import (
	"fmt"

	"rocketvault/model"
)

// applySecretUpdate merges an update request onto the current secret and
// returns a new entity. It performs no I/O and no authorization: authorization
// lives entirely in the scope passed to the repository, and encryption is
// injected so the function is unit-testable without a database.
//
// The returned secret always carries an incremented version. Nil request
// fields mean "no change".
func applySecretUpdate(current *model.Secret, req UpdateSecretRequest,
	encrypt func(string) (string, error)) (*model.Secret, error) {
	if current == nil {
		return nil, fmt.Errorf("cannot apply an update to a nil secret")
	}

	updated := *current
	updated.Version++

	if req.ContentType != nil {
		if err := validateContentType(*req.ContentType); err != nil {
			return nil, err
		}
		updated.ContentType = *req.ContentType
	}
	if req.Name != nil {
		updated.Name = *req.Name
	}
	if req.Enabled != nil {
		updated.Enabled = *req.Enabled
	}
	if req.ExpiresAt != nil {
		updated.ExpiresAt = req.ExpiresAt
	}
	if req.NotBefore != nil {
		updated.NotBefore = req.NotBefore
	}
	if req.Value != nil {
		encrypted, err := encrypt(*req.Value)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt updated secret: %w", err)
		}
		updated.Value = encrypted
	}

	return &updated, nil
}
