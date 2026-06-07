//go:build integration

// Package repositories_test integration suite runs the real repositories
// against a live PostgreSQL container to prove dual-engine support. Run with:
//
//	go test -tags=integration ./internal/repositories/...
//
// It requires Docker. The default `go test ./...` run skips this file.
package repositories_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

// newPostgresConn boots a postgres:16 container, runs the full schema setup,
// and returns a dialect-aware connection plus a cleanup func.
func newPostgresConn(t *testing.T) (*rvdb.Conn, func()) {
	t.Helper()
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("rocketvault"),
		tcpostgres.WithUsername("rv"),
		tcpostgres.WithPassword("rv-secret"),
		tcpostgres.BasicWaitStrategies(),
		tcpostgres.WithSQLDriver("postgres"),
		// Belt-and-suspenders: also wait for the readiness log line.
		testcontainers.WithAdditionalWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err, "start postgres container")

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	sqlDB, err := sql.Open("postgres", dsn)
	require.NoError(t, err)

	// Wait for the server to accept connections.
	require.Eventually(t, func() bool {
		return sqlDB.PingContext(ctx) == nil
	}, 60*time.Second, 500*time.Millisecond, "postgres did not become ready")

	// Run schema, migrations, and seeds against Postgres.
	repo := rvdb.NewRepository(logging.InitLogger())
	require.NoError(t, repo.SetupSchema(sqlDB, rvdb.Postgres), "setup schema on postgres")

	conn := rvdb.NewConn(sqlDB, rvdb.Postgres)

	cleanup := func() {
		sqlDB.Close()
		_ = container.Terminate(ctx)
	}
	return conn, cleanup
}

// seedUser inserts a user row so foreign-key-ish references resolve.
func seedUser(t *testing.T, conn *rvdb.Conn, id uuid.UUID) {
	t.Helper()
	_, err := conn.ExecContext(context.Background(),
		"INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
		id.String(), "user-"+id.String()[:8], "hash", "user",
	)
	require.NoError(t, err)
}

func TestPostgres_SecretRoundTrip_BinaryValue(t *testing.T) {
	conn, cleanup := newPostgresConn(t)
	defer cleanup()
	ctx := context.Background()
	log := logging.InitLogger()

	userID := uuid.New()
	seedUser(t, conn, userID)

	repo := repositories.NewSecretRepository(conn, log)

	// A base64-encoded "encrypted" blob — the real storage format. This proves
	// the TEXT column round-trips non-trivial ASCII on Postgres.
	rawCipher := []byte{0x00, 0x01, 0xff, 0xfe, 0x10, 0x42, 0x7f}
	encoded := base64.StdEncoding.EncodeToString(rawCipher)

	secret := &model.Secret{
		ID:      uuid.New(),
		UserID:  userID,
		VaultID: uuid.MustParse(model.DefaultVaultID),
		Name:    "db-password",
		Value:   encoded,
		Version: 1,
		Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, secret))

	got, err := repo.Read(ctx, secret.ID)
	require.NoError(t, err)
	require.Equal(t, encoded, got.Value, "base64 value must round-trip exactly")

	decoded, err := base64.StdEncoding.DecodeString(got.Value)
	require.NoError(t, err)
	require.Equal(t, rawCipher, decoded, "decoded bytes must match original")
}

func TestPostgres_KeyWithTags_RoundTrip(t *testing.T) {
	conn, cleanup := newPostgresConn(t)
	defer cleanup()
	ctx := context.Background()
	log := logging.InitLogger()

	userID := uuid.New()
	seedUser(t, conn, userID)

	repo := repositories.NewKeyRepository(conn, log)

	key := &model.Key{
		ID:        uuid.New(),
		UserID:    userID,
		VaultID:   uuid.MustParse(model.DefaultVaultID),
		Name:      "signing-key",
		Type:      "RSA",
		Value:     base64.StdEncoding.EncodeToString([]byte("pem-bytes")),
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
		Bits:      2048,
		Tags:      []string{"prod", "signing"},
	}
	require.NoError(t, repo.Create(ctx, key))

	// Read exercises GetTags, which previously passed a raw uuid.UUID instead of
	// id.String() and would silently return no tags on Postgres.
	got, err := repo.Read(ctx, key.ID)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"prod", "signing"}, got.Tags,
		"tags must round-trip on Postgres (guards the GetTags id.String fix)")
}

func TestPostgres_SecretTags_UpsertIgnore(t *testing.T) {
	conn, cleanup := newPostgresConn(t)
	defer cleanup()
	ctx := context.Background()
	log := logging.InitLogger()

	userID := uuid.New()
	seedUser(t, conn, userID)

	// Create a real secret first: Postgres enforces the secret_tags -> secrets
	// foreign key (SQLite leaves FKs off by default), so the parent row must exist.
	secretRepo := repositories.NewSecretRepository(conn, log)
	secret := &model.Secret{
		ID:      uuid.New(),
		UserID:  userID,
		VaultID: uuid.MustParse(model.DefaultVaultID),
		Name:    "tagged-secret",
		Value:   base64.StdEncoding.EncodeToString([]byte("v")),
		Version: 1,
		Enabled: true,
	}
	require.NoError(t, secretRepo.Create(ctx, secret))

	tagRepo := repositories.NewSecretTagRepository(conn)

	// Adding the same tag twice must not error — UpsertIgnore becomes
	// ON CONFLICT DO NOTHING on Postgres.
	require.NoError(t, tagRepo.AddTags(ctx, secret.ID, []string{"alpha", "beta"}))
	require.NoError(t, tagRepo.AddTags(ctx, secret.ID, []string{"alpha", "gamma"}),
		"re-adding an existing tag must be ignored, not error")

	tags, err := tagRepo.GetTags(ctx, secret.ID)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"alpha", "beta", "gamma"}, tags)
}

func TestPostgres_DefaultVaultSeeded(t *testing.T) {
	conn, cleanup := newPostgresConn(t)
	defer cleanup()
	ctx := context.Background()

	// The bootstrap seed path runs on the raw *sql.DB before the wrapper; this
	// confirms the rebound seed queries executed on Postgres.
	var count int
	err := conn.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM vaults WHERE id = ?", model.DefaultVaultID,
	).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count, "default vault must be seeded on Postgres")
}
