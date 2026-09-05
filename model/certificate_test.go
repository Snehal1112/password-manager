package model_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"rocketvault/model"
)

func TestCertificate_Clone_IndependentCopy(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	caID := uuid.New()
	c := &model.Certificate{
		ID:        uuid.New(),
		Name:      "original",
		Tags:      []string{"a", "b"},
		ExpiresAt: &exp,
		CACertID:  &caID,
	}
	clone := c.Clone()

	clone.Name = "changed"
	clone.Tags[0] = "mutated"
	*clone.ExpiresAt = time.Now().Add(2 * time.Hour)
	*clone.CACertID = uuid.New()

	assert.Equal(t, "original", c.Name, "mutating the clone's Name must not affect the original")
	assert.Equal(t, "a", c.Tags[0], "mutating the clone's Tags must not affect the original's backing array")
	assert.NotEqual(t, *c.ExpiresAt, *clone.ExpiresAt, "mutating the clone's ExpiresAt must not affect the original's pointee")
	assert.NotEqual(t, *c.CACertID, *clone.CACertID, "mutating the clone's CACertID must not affect the original's pointee")
}

func TestCertificate_Clone_NilPointerFieldsStayNil(t *testing.T) {
	c := &model.Certificate{ID: uuid.New(), Name: "x"}
	clone := c.Clone()
	assert.Nil(t, clone.ExpiresAt)
	assert.Nil(t, clone.NotBefore)
	assert.Nil(t, clone.DeletedAt)
	assert.Nil(t, clone.ScheduledPurgeAt)
	assert.Nil(t, clone.CACertID)
}
