package rekey

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
)

// DefaultBatchSize is how many row updates share one transaction when the
// caller does not choose.
const DefaultBatchSize = 100

// masterKeySize is the AES-256 key length in raw bytes.
const masterKeySize = 32

// Options configures a rotation run. OldKey and NewKey are read from
// environment variables by the CLI layer (cmd/master_key.go) and never
// accepted as command-line arguments, so key material cannot leak through
// shell history or a process listing.
type Options struct {
	// OldKey is the 32-byte key the stored data is currently sealed with.
	OldKey []byte
	// NewKey is the 32-byte key to reseal the data with.
	NewKey []byte
	// DryRun reports what would change without writing anything.
	DryRun bool
	// BatchSize is the number of row updates per transaction.
	BatchSize int
}

// TargetReport summarises what happened to one table column.
type TargetReport struct {
	Table           string
	Column          string
	Total           int
	ReEncrypted     int
	AlreadyNewKey   int
	SkippedExternal int
}

// Report summarises a whole rotation run.
type Report struct {
	Targets []TargetReport
	DryRun  bool
}

// TotalReEncrypted returns how many rows were resealed across all targets (or,
// for a dry run, how many would be).
func (r Report) TotalReEncrypted() int {
	total := 0
	for _, target := range r.Targets {
		total += target.ReEncrypted
	}
	return total
}

// Rekeyer re-encrypts master-key-sealed columns from one key to another. It is
// the mechanism behind master key rotation: one instance is built per CLI
// invocation of "rocketvault master-key rotate" and discarded once Run
// returns, so it holds no state across runs beyond the open database
// connection.
type Rekeyer struct {
	db     rvdb.DB
	logger *logging.Logger
}

// pendingUpdate is one planned row rewrite.
type pendingUpdate struct {
	keys     []any
	oldValue string
	newValue string
}

// New creates a Rekeyer bound to a dialect-aware database connection.
//
// Parameters:
//
//	database: The dialect-aware connection whose rows will be rewritten.
//	logger: The logger used for per-batch progress counters.
//
// Returns:
//
//	A Rekeyer ready to Run.
func New(database rvdb.DB, logger *logging.Logger) *Rekeyer {
	return &Rekeyer{db: database, logger: logger}
}

// Run re-encrypts every master-key-sealed column from opts.OldKey to
// opts.NewKey, one target at a time. Each target is fully read and classified
// before any of its rows are written, so a value that opens with neither key
// aborts that target with no partial write. Targets completed before a failure
// stay migrated; re-running with the same key pair resumes safely because
// already-migrated rows are detected and skipped.
//
// Parameters:
//
//	ctx: The context for the run.
//	opts: The keys, dry-run flag, and batch size.
//
// Returns:
//
//	A report covering every target processed so far, and an error if the run
//	could not complete.
func (r *Rekeyer) Run(ctx context.Context, opts Options) (*Report, error) {
	if len(opts.OldKey) != masterKeySize || len(opts.NewKey) != masterKeySize {
		return nil, fmt.Errorf("both master keys must be %d raw bytes", masterKeySize)
	}
	if bytes.Equal(opts.OldKey, opts.NewKey) {
		return nil, fmt.Errorf("the new master key is identical to the old one — nothing to rotate " +
			"(if MASTER_KEY is exported in this shell it takes precedence over the config file, " +
			"so the old key resolved to the new one)")
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = DefaultBatchSize
	}

	report := &Report{DryRun: opts.DryRun}
	for _, target := range Targets() {
		targetReport, err := r.processTarget(ctx, target, opts)
		if targetReport != nil {
			report.Targets = append(report.Targets, *targetReport)
		}
		if err != nil {
			return report, fmt.Errorf("%s.%s: %w", target.Table, target.Column, err)
		}
	}
	return report, nil
}

// processTarget plans one target, then applies it unless this is a dry run.
func (r *Rekeyer) processTarget(ctx context.Context, target Target, opts Options) (*TargetReport, error) {
	pending, targetReport, err := r.planTarget(ctx, target, opts)
	if err != nil {
		return nil, err
	}
	if opts.DryRun || len(pending) == 0 {
		return targetReport, nil
	}
	if err := r.applyTarget(ctx, target, pending, opts.BatchSize); err != nil {
		return targetReport, err
	}
	return targetReport, nil
}

// planTarget reads and classifies every row of one target without writing.
func (r *Rekeyer) planTarget(ctx context.Context, target Target, opts Options) ([]pendingUpdate, *TargetReport, error) {
	rows, err := r.db.QueryContext(ctx, target.SelectSQL())
	if err != nil {
		return nil, nil, fmt.Errorf("read rows: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	targetReport := &TargetReport{Table: target.Table, Column: target.Column}
	var pending []pendingUpdate

	for rows.Next() {
		// Key columns are scanned as strings on both dialects: SQLite applies
		// column affinity and Postgres infers the parameter type, so an
		// integer key column such as key_versions.version round-trips
		// correctly as text.
		keyValues := make([]string, len(target.KeyColumns))
		scanTargets := make([]any, 0, len(target.KeyColumns)+1)
		for i := range keyValues {
			scanTargets = append(scanTargets, &keyValues[i])
		}
		var value string
		scanTargets = append(scanTargets, &value)

		if err := rows.Scan(scanTargets...); err != nil {
			return nil, nil, fmt.Errorf("scan row: %w", err)
		}
		targetReport.Total++

		act, resealed, err := classify(value, opts.OldKey, opts.NewKey)
		if err != nil {
			return nil, nil, fmt.Errorf("row %s: %w", strings.Join(keyValues, "/"), err)
		}

		switch act {
		case actionSkipExternal:
			targetReport.SkippedExternal++
		case actionAlreadyNewKey:
			targetReport.AlreadyNewKey++
		case actionReEncrypt:
			targetReport.ReEncrypted++
			pending = append(pending, pendingUpdate{
				keys:     toArgs(keyValues),
				oldValue: value,
				newValue: resealed,
			})
		default:
			// Unreachable today: classify only returns actionInvalid together
			// with an error, which is handled above. It aborts rather than
			// falling through, so a future action added to classify cannot
			// silently leave a row sealed with the old key.
			return nil, nil, fmt.Errorf("row %s: unhandled classification %d",
				strings.Join(keyValues, "/"), act)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate rows: %w", err)
	}

	return pending, targetReport, nil
}

// applyTarget writes the planned updates in batched transactions.
func (r *Rekeyer) applyTarget(ctx context.Context, target Target, pending []pendingUpdate, batchSize int) error {
	updateSQL := target.UpdateSQL()

	for start := 0; start < len(pending); start += batchSize {
		end := start + batchSize
		if end > len(pending) {
			end = len(pending)
		}
		if err := r.applyBatch(ctx, updateSQL, pending[start:end]); err != nil {
			return err
		}
		r.logger.WithFields(logrus.Fields{
			"table":   target.Table,
			"column":  target.Column,
			"updated": end,
			"total":   len(pending),
		}).Info("Master key rotation progress")
	}
	return nil
}

// applyBatch rewrites one batch of rows inside a single transaction. Each
// update is guarded by the ciphertext read during the plan phase, so a row
// changed by a still-running server aborts the run instead of being clobbered.
// This is why the documented procedure stops the server first: rotation is not
// designed to race a live writer, only to detect and refuse the race if the
// operator's "stop the server" step was skipped.
func (r *Rekeyer) applyBatch(ctx context.Context, updateSQL string, batch []pendingUpdate) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	for _, update := range batch {
		args := make([]any, 0, len(update.keys)+2)
		args = append(args, update.newValue)
		args = append(args, update.keys...)
		args = append(args, update.oldValue)

		result, err := tx.ExecContext(ctx, updateSQL, args...)
		if err != nil {
			tx.Rollback() //nolint:errcheck,gosec
			return fmt.Errorf("update row %v: %w", update.keys, err)
		}

		affected, err := result.RowsAffected()
		if err != nil {
			tx.Rollback() //nolint:errcheck,gosec
			return fmt.Errorf("rows affected for row %v: %w", update.keys, err)
		}
		if affected != 1 {
			tx.Rollback() //nolint:errcheck,gosec
			return fmt.Errorf("row %v changed while the rotation was running "+
				"(%d rows updated, expected 1) — stop the RocketVault server and re-run",
				update.keys, affected)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit batch: %w", err)
	}
	return nil
}

// toArgs converts scanned key-column values into query arguments.
func toArgs(values []string) []any {
	args := make([]any, len(values))
	for i, value := range values {
		args[i] = value
	}
	return args
}
