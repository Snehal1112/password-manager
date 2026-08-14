package model_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"rocketvault/model"
)

func TestSecret_Clone_IndependentCopy(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	s := &model.Secret{
		ID:        uuid.New(),
		Name:      "original",
		Tags:      []string{"a", "b"},
		ExpiresAt: &exp,
	}
	clone := s.Clone()

	clone.Name = "changed"
	clone.Tags[0] = "mutated"
	*clone.ExpiresAt = time.Now().Add(2 * time.Hour)

	assert.Equal(t, "original", s.Name, "mutating the clone's Name must not affect the original")
	assert.Equal(t, "a", s.Tags[0], "mutating the clone's Tags must not affect the original's backing array")
	assert.NotEqual(t, *s.ExpiresAt, *clone.ExpiresAt, "mutating the clone's ExpiresAt must not affect the original's pointee")
}

func TestSecret_Clone_NilPointerFieldsStayNil(t *testing.T) {
	s := &model.Secret{ID: uuid.New(), Name: "x"}
	clone := s.Clone()
	assert.Nil(t, clone.ExpiresAt)
	assert.Nil(t, clone.NotBefore)
	assert.Nil(t, clone.DeletedAt)
	assert.Nil(t, clone.ScheduledPurgeAt)
}
