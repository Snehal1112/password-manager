package keys

import (
	"fmt"

	"rocketvault/model"
)

// applyKeyUpdate merges an update request onto the current key and returns a
// new entity. It performs no I/O and no authorization: authorization lives
// entirely in the scope passed to the repository.
//
// Nil request fields mean "no change". A non-nil empty Tags slice clears all
// tags, matching the pre-refactor behaviour of UpdateKey.
func applyKeyUpdate(current *model.Key, req UpdateKeyRequest) (*model.Key, error) {
	if current == nil {
		return nil, fmt.Errorf("cannot apply an update to a nil key")
	}

	updated := *current

	if req.Name != nil {
		updated.Name = *req.Name
	}
	if req.Tags != nil {
		updated.Tags = req.Tags
	}
	if req.Revoked != nil {
		updated.Revoked = *req.Revoked
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

	return &updated, nil
}
