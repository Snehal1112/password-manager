/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package secrets

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"password-manager/common"
	"password-manager/internal/logging"
)

func TestRotationPolicyRepository(t *testing.T) {
	// Setup test database
	db, cleanup := setupTestDB(t)
	defer cleanup()

	logger := logging.InitLogger()
	repo := NewRotationPolicyRepository(db, logger)
	ctx := context.Background()

	// Create test user
	userID := createTestUser(t, db)

	t.Run("Create", func(t *testing.T) {
		policy := &RotationPolicy{
			UserID:       userID,
			Name:         "Test Policy",
			Description:  "Test rotation policy",
			IntervalDays: 30,
			Enabled:      true,
			ReminderDays: 7,
			AutoRotate:   true,
		}

		err := repo.Create(ctx, policy)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, policy.ID)
		assert.NotZero(t, policy.CreatedAt)
		assert.NotZero(t, policy.UpdatedAt)
	})

	t.Run("Read", func(t *testing.T) {
		// First create a policy
		policy := &RotationPolicy{
			UserID:       userID,
			Name:         "Read Test Policy",
			Description:  "Test policy for reading",
			IntervalDays: 60,
			Enabled:      true,
			ReminderDays: 14,
			AutoRotate:   false,
		}
		err := repo.Create(ctx, policy)
		require.NoError(t, err)

		// Read it back
		readPolicy, err := repo.Read(ctx, policy.ID)
		require.NoError(t, err)
		assert.Equal(t, policy.Name, readPolicy.Name)
		assert.Equal(t, policy.IntervalDays, readPolicy.IntervalDays)
		assert.Equal(t, policy.AutoRotate, readPolicy.AutoRotate)
	})

	t.Run("Update", func(t *testing.T) {
		// Create a policy
		policy := &RotationPolicy{
			UserID:       userID,
			Name:         "Update Test Policy",
			Description:  "Test policy for updating",
			IntervalDays: 30,
			Enabled:      true,
			ReminderDays: 7,
			AutoRotate:   false,
		}
		err := repo.Create(ctx, policy)
		require.NoError(t, err)

		// Update it
		policy.Name = "Updated Policy"
		policy.IntervalDays = 45
		policy.AutoRotate = true
		err = repo.Update(ctx, policy)
		require.NoError(t, err)

		// Read it back to verify
		updatedPolicy, err := repo.Read(ctx, policy.ID)
		require.NoError(t, err)
		assert.Equal(t, "Updated Policy", updatedPolicy.Name)
		assert.Equal(t, 45, updatedPolicy.IntervalDays)
		assert.True(t, updatedPolicy.AutoRotate)
	})

	t.Run("Delete", func(t *testing.T) {
		// Create a policy
		policy := &RotationPolicy{
			UserID:       userID,
			Name:         "Delete Test Policy",
			Description:  "Test policy for deletion",
			IntervalDays: 30,
			Enabled:      true,
			ReminderDays: 7,
			AutoRotate:   false,
		}
		err := repo.Create(ctx, policy)
		require.NoError(t, err)

		// Delete it
		err = repo.Delete(ctx, policy.ID)
		require.NoError(t, err)

		// Try to read it back - should fail
		_, err = repo.Read(ctx, policy.ID)
		assert.Error(t, err)
	})

	t.Run("ListByUser", func(t *testing.T) {
		// Create multiple policies
		policies := []*RotationPolicy{
			{
				UserID:       userID,
				Name:         "Policy 1",
				Description:  "First test policy",
				IntervalDays: 30,
				Enabled:      true,
				ReminderDays: 7,
				AutoRotate:   false,
			},
			{
				UserID:       userID,
				Name:         "Policy 2",
				Description:  "Second test policy",
				IntervalDays: 60,
				Enabled:      false,
				ReminderDays: 14,
				AutoRotate:   true,
			},
		}

		for _, policy := range policies {
			err := repo.Create(ctx, policy)
			require.NoError(t, err)
		}

		// List them
		userPolicies, err := repo.ListByUser(ctx, userID)
		require.NoError(t, err)
		assert.True(t, len(userPolicies) >= 2) // May have policies from other tests

		// Find our test policies
		found := 0
		for _, p := range userPolicies {
			if p.Name == "Policy 1" || p.Name == "Policy 2" {
				found++
			}
		}
		assert.Equal(t, 2, found)
	})
}

func TestSecretPolicyAssignment(t *testing.T) {
	// Setup test database
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Set up viper configuration for encryption
	viper.Set("master_key", "***SECRET-REMOVED-2026-08-17***")
	viper.Set("jwt_secret", "test-jwt-secret")

	logger := logging.InitLogger()
	repo := NewRotationPolicyRepository(db, logger)
	ctx := context.Background()

	// Create test user and secret
	userID := createTestUser(t, db)
	secretID := createTestSecret(t, db, userID)

	t.Run("AssignToSecret", func(t *testing.T) {
		// Create a policy
		policy := &RotationPolicy{
			UserID:       userID,
			Name:         "Assignment Test Policy",
			Description:  "Test policy for assignment",
			IntervalDays: 30,
			Enabled:      true,
			ReminderDays: 7,
			AutoRotate:   false,
		}
		err := repo.Create(ctx, policy)
		require.NoError(t, err)

		// Assign to secret
		err = repo.AssignToSecret(ctx, secretID, policy.ID)
		require.NoError(t, err)

		// Verify assignment
		policies, err := repo.GetSecretPolicies(ctx, secretID)
		require.NoError(t, err)
		assert.Len(t, policies, 1)
		assert.Equal(t, policy.ID, policies[0].PolicyID)
		assert.Equal(t, secretID, policies[0].SecretID)
	})

	t.Run("RemoveFromSecret", func(t *testing.T) {
		// Create a separate secret for this test
		removalSecretID := createTestSecret(t, db, userID)

		// Create and assign a policy
		policy := &RotationPolicy{
			UserID:       userID,
			Name:         "Removal Test Policy",
			Description:  "Test policy for removal",
			IntervalDays: 30,
			Enabled:      true,
			ReminderDays: 7,
			AutoRotate:   false,
		}
		err := repo.Create(ctx, policy)
		require.NoError(t, err)

		err = repo.AssignToSecret(ctx, removalSecretID, policy.ID)
		require.NoError(t, err)

		// Remove from secret
		err = repo.RemoveFromSecret(ctx, removalSecretID, policy.ID)
		require.NoError(t, err)

		// Verify removal
		policies, err := repo.GetSecretPolicies(ctx, removalSecretID)
		require.NoError(t, err)
		assert.Len(t, policies, 0)
	})
}

func TestRotationHistory(t *testing.T) {
	// Setup test database
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Set up viper configuration for encryption
	viper.Set("master_key", "***SECRET-REMOVED-2026-08-17***")
	viper.Set("jwt_secret", "test-jwt-secret")

	logger := logging.InitLogger()
	repo := NewRotationPolicyRepository(db, logger)
	ctx := context.Background()

	// Create test user and secret
	userID := createTestUser(t, db)
	secretID := createTestSecret(t, db, userID)

	t.Run("RecordRotation", func(t *testing.T) {
		history := &RotationHistory{
			SecretID:        secretID,
			PreviousVersion: 1,
			NewVersion:      2,
			TriggeredBy:     "manual",
			Notes:           "Test rotation",
		}

		err := repo.RecordRotation(ctx, history)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, history.ID)
		assert.NotZero(t, history.RotatedAt)
	})

	t.Run("GetRotationHistory", func(t *testing.T) {
		// Create a separate secret for this test
		historySecretID := createTestSecret(t, db, userID)

		// Record a few rotations
		for i := 0; i < 3; i++ {
			history := &RotationHistory{
				SecretID:        historySecretID,
				PreviousVersion: i + 1,
				NewVersion:      i + 2,
				TriggeredBy:     "manual",
				Notes:           fmt.Sprintf("Test rotation %d", i+1),
			}
			err := repo.RecordRotation(ctx, history)
			require.NoError(t, err)
		}

		// Get history
		histories, err := repo.GetRotationHistory(ctx, historySecretID)
		require.NoError(t, err)
		assert.Len(t, histories, 3)

		// Verify they're ordered by date (most recent first)
		assert.True(t, histories[0].RotatedAt.After(histories[1].RotatedAt) ||
			histories[0].RotatedAt.Equal(histories[1].RotatedAt))
	})
}

func TestRotationScheduler(t *testing.T) {
	// Setup test database
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Set up viper configuration for encryption
	viper.Set("master_key", "***SECRET-REMOVED-2026-08-17***")
	viper.Set("jwt_secret", "test-jwt-secret")

	logger := logging.InitLogger()
	repo := NewRotationPolicyRepository(db, logger)
	secretRepo := NewSecretRepository(db, logger)
	scheduler := NewRotationScheduler(db, logger, repo, secretRepo)
	ctx := context.Background()

	// Create test user and secret
	userID := createTestUser(t, db)
	secretID := createTestSecret(t, db, userID)

	t.Run("ManualRotate", func(t *testing.T) {
		// Create a policy
		policy := &RotationPolicy{
			UserID:       userID,
			Name:         "Scheduler Test Policy",
			Description:  "Test policy for scheduler",
			IntervalDays: 30,
			Enabled:      true,
			ReminderDays: 7,
			AutoRotate:   true,
		}
		err := repo.Create(ctx, policy)
		require.NoError(t, err)

		// Assign to secret
		err = repo.AssignToSecret(ctx, secretID, policy.ID)
		require.NoError(t, err)

		// Perform manual rotation
		err = scheduler.ManualRotate(ctx, secretID, policy.ID, userID)
		require.NoError(t, err)

		// Verify secret was updated
		updatedSecret, err := secretRepo.Read(ctx, secretID)
		require.NoError(t, err)
		assert.Equal(t, 2, updatedSecret.Version) // Should be incremented

		// Verify rotation was recorded
		history, err := repo.GetRotationHistory(ctx, secretID)
		require.NoError(t, err)
		assert.Len(t, history, 1)
		assert.Equal(t, "manual", history[0].TriggeredBy)
		assert.Equal(t, 1, history[0].PreviousVersion)
		assert.Equal(t, 2, history[0].NewVersion)
	})

	t.Run("CheckAndCreateReminders", func(t *testing.T) {
		// Create a policy with reminder
		policy := &RotationPolicy{
			UserID:       userID,
			Name:         "Reminder Test Policy",
			Description:  "Test policy for reminders",
			IntervalDays: 30,
			Enabled:      true,
			ReminderDays: 7,
			AutoRotate:   false,
		}
		err := repo.Create(ctx, policy)
		require.NoError(t, err)

		// Assign to secret
		err = repo.AssignToSecret(ctx, secretID, policy.ID)
		require.NoError(t, err)

		// Set next rotation to tomorrow
		tomorrow := time.Now().AddDate(0, 0, 1)
		query := `UPDATE secret_policies SET next_rotation_at = ? WHERE secret_id = ? AND policy_id = ?`
		_, err = db.ExecContext(ctx, query, tomorrow, secretID.String(), policy.ID.String())
		require.NoError(t, err)

		// Check and create reminders
		err = scheduler.CheckAndCreateReminders(ctx, userID)
		require.NoError(t, err)

		// Verify reminder was created
		reminders, err := repo.GetUpcomingReminders(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, reminders, 1)
		assert.Equal(t, "upcoming", reminders[0].ReminderType)
	})
}

// Helper functions for tests

func createTestUser(t *testing.T, db *sql.DB) uuid.UUID {
	userID := uuid.New()
	query := `
		INSERT INTO users (id, username, password_hash, role, created_at)
		VALUES (?, ?, ?, ?, ?)
	`
	_, err := db.Exec(query, userID.String(), "testuser", "hash", "user", time.Now())
	require.NoError(t, err)
	return userID
}

func createTestSecret(t *testing.T, db *sql.DB, userID uuid.UUID) uuid.UUID {
	secretID := uuid.New()

	// Encrypt the test value
	encryptedValue, err := common.EncryptSecret("testvalue")
	require.NoError(t, err)

	query := `
		INSERT INTO secrets (id, user_id, name, value, version, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	_, err = db.Exec(query, secretID.String(), userID.String(), "testsecret", encryptedValue, 1, time.Now())
	require.NoError(t, err)
	return secretID
}
