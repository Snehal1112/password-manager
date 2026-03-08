package repositories

import (
"context"
"database/sql"
"fmt"
"time"

"github.com/google/uuid"

"rocketvault/internal/domain"
)

// OAuth2ClientRepositoryInterface defines CRUD operations for OAuth2 clients.
// Repositories handle only data access — no business logic.
type OAuth2ClientRepositoryInterface interface {
	Create(ctx context.Context, client *domain.OAuth2Client) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.OAuth2Client, error)
	// FindByName looks up a client by its unique name (the RFC 6749 client_id).
	FindByName(ctx context.Context, name string) (*domain.OAuth2Client, error)
	List(ctx context.Context) ([]*domain.OAuth2Client, error)
	Update(ctx context.Context, client *domain.OAuth2Client) error
	Delete(ctx context.Context, id uuid.UUID) error
}

type oauth2ClientRepository struct {
	db *sql.DB
}

// NewOAuth2ClientRepository creates a new OAuth2ClientRepositoryInterface backed by db.
func NewOAuth2ClientRepository(db *sql.DB) OAuth2ClientRepositoryInterface {
	return &oauth2ClientRepository{db: db}
}

func (r *oauth2ClientRepository) Create(ctx context.Context, c *domain.OAuth2Client) error {
	_, err := r.db.ExecContext(ctx,
`INSERT INTO oauth2_clients (id, name, client_secret, description, enabled, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
c.ID.String(), c.Name, c.ClientSecret, c.Description, c.Enabled, c.CreatedAt, c.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("oauth2ClientRepository.Create: %w", err)
	}
	return nil
}

func (r *oauth2ClientRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.OAuth2Client, error) {
	row := r.db.QueryRowContext(ctx,
`SELECT id, name, client_secret, description, enabled, created_at, expires_at
		 FROM oauth2_clients WHERE id = ?`, id.String())
	return scanOAuth2Client(row)
}

func (r *oauth2ClientRepository) FindByName(ctx context.Context, name string) (*domain.OAuth2Client, error) {
	row := r.db.QueryRowContext(ctx,
`SELECT id, name, client_secret, description, enabled, created_at, expires_at
		 FROM oauth2_clients WHERE name = ?`, name)
	return scanOAuth2Client(row)
}

func (r *oauth2ClientRepository) List(ctx context.Context) ([]*domain.OAuth2Client, error) {
	rows, err := r.db.QueryContext(ctx,
`SELECT id, name, client_secret, description, enabled, created_at, expires_at
		 FROM oauth2_clients ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("oauth2ClientRepository.List: %w", err)
	}
	defer rows.Close()

	var clients []*domain.OAuth2Client
	for rows.Next() {
		c, err := scanOAuth2ClientRow(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

func (r *oauth2ClientRepository) Update(ctx context.Context, c *domain.OAuth2Client) error {
	_, err := r.db.ExecContext(ctx,
`UPDATE oauth2_clients SET name=?, client_secret=?, description=?, enabled=?, expires_at=?
		 WHERE id=?`,
c.Name, c.ClientSecret, c.Description, c.Enabled, c.ExpiresAt, c.ID.String(),
	)
	if err != nil {
		return fmt.Errorf("oauth2ClientRepository.Update: %w", err)
	}
	return nil
}

func (r *oauth2ClientRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM oauth2_clients WHERE id=?`, id.String())
	if err != nil {
		return fmt.Errorf("oauth2ClientRepository.Delete: %w", err)
	}
	return nil
}

// scanOAuth2Client scans a single sql.Row into an OAuth2Client.
func scanOAuth2Client(row *sql.Row) (*domain.OAuth2Client, error) {
	var c domain.OAuth2Client
	var idStr string
	var expiresAt sql.NullTime
	var createdAt time.Time

	err := row.Scan(&idStr, &c.Name, &c.ClientSecret, &c.Description, &c.Enabled, &createdAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("oauth2 client not found")
	}
	if err != nil {
		return nil, fmt.Errorf("scanOAuth2Client: %w", err)
	}

	c.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("scanOAuth2Client: invalid uuid: %w", err)
	}
	c.CreatedAt = createdAt
	if expiresAt.Valid {
		t := expiresAt.Time
		c.ExpiresAt = &t
	}
	return &c, nil
}

// scanOAuth2ClientRow scans from sql.Rows (multiple results).
func scanOAuth2ClientRow(rows *sql.Rows) (*domain.OAuth2Client, error) {
	var c domain.OAuth2Client
	var idStr string
	var expiresAt sql.NullTime
	var createdAt time.Time

	err := rows.Scan(&idStr, &c.Name, &c.ClientSecret, &c.Description, &c.Enabled, &createdAt, &expiresAt)
	if err != nil {
		return nil, fmt.Errorf("scanOAuth2ClientRow: %w", err)
	}

	c.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("scanOAuth2ClientRow: invalid uuid: %w", err)
	}
	c.CreatedAt = createdAt
	if expiresAt.Valid {
		t := expiresAt.Time
		c.ExpiresAt = &t
	}
	return &c, nil
}
