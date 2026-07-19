// Package softdelete provides background scheduling for permanent deletion of
// soft-deleted records whose retention period has expired.
package softdelete

import (
	"context"
	"fmt"
	"time"

	"rocketvault/config"
	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
)

// PurgeScheduler runs daily and permanently deletes soft-deleted items
// whose retention period has expired and purge_protection is false.
type PurgeScheduler struct {
	db   rvdb.DB
	cfg  config.SoftDeleteConfig
	log  *logging.Logger
	done chan struct{}
}

// NewPurgeScheduler creates a new PurgeScheduler.
func NewPurgeScheduler(db rvdb.DB, cfg config.SoftDeleteConfig, log *logging.Logger) *PurgeScheduler {
	return &PurgeScheduler{db: db, cfg: cfg, log: log, done: make(chan struct{})}
}

// Start launches the scheduler in a background goroutine.
func (s *PurgeScheduler) Start(ctx context.Context) {
	go s.run(ctx)
}

// Stop signals the scheduler to stop.
func (s *PurgeScheduler) Stop() {
	close(s.done)
}

func (s *PurgeScheduler) run(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// Run once immediately on startup.
	s.purgeExpired(ctx)

	for {
		select {
		case <-ticker.C:
			s.purgeExpired(ctx)
		case <-s.done:
			return
		case <-ctx.Done():
			return
		}
	}
}

// purgeExpired permanently deletes items past their retention period.
func (s *PurgeScheduler) purgeExpired(ctx context.Context) {
	cutoff := time.Now().AddDate(0, 0, -s.cfg.RetentionDays)
	tables := []string{"secrets", "keys", "certificates"}
	for _, table := range tables {
		query := fmt.Sprintf(
			`DELETE FROM %s WHERE deleted_at IS NOT NULL AND deleted_at < ? AND purge_protection = FALSE`,
			table,
		)
		result, err := s.db.ExecContext(ctx, query, cutoff)
		if err != nil {
			s.log.WithError(err).Errorf("auto-purge failed for table %s", table)
			continue
		}
		n, _ := result.RowsAffected()
		if n > 0 {
			s.log.Infof("auto-purged %d expired items from %s", n, table)
		}
	}
}
