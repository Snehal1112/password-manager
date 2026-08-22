package db

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
)

// ResolveNameCollisions renames duplicate (vault_id, name) rows in the given
// resource table so the new unique index can be created. It keeps the first row
// of each duplicate group and renames the rest to "{name}-{short-id}". It returns
// the number of rows renamed and logs each rename.
//
// Only ACTIVE rows (deleted_at IS NULL) are considered, matching the partial
// unique index finalizeVaultIndexes creates (B50). A soft-deleted row is
// invisible to that index, so it can never cause a collision: sharing a name
// with an active row, or with another soft-deleted row, is legal and must not
// trigger a rename. Renaming on those cases would be pure churn, and could
// rename a row that was never going to violate the constraint.
//
// The table name comes only from internal callers using constant table names,
// never from user input, so the fmt.Sprintf into SQL is safe here. Every table
// this is called for (secrets, keys, certificates) has a deleted_at column by
// the time it runs -- migrateSchema adds it before finalizeVaultIndexes.
func ResolveNameCollisions(ctx context.Context, d DB, table string) (int, error) {
	rows, err := d.QueryContext(ctx, fmt.Sprintf(
		"SELECT id, name, vault_id FROM %s WHERE deleted_at IS NULL ORDER BY vault_id, name, id", table))
	if err != nil {
		return 0, fmt.Errorf("scan %s for collisions: %w", table, err)
	}
	defer rows.Close() //nolint:errcheck

	type rec struct{ id, name, vault string }
	var all []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.id, &r.name, &r.vault); err != nil {
			return 0, err
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	seen := map[string]bool{}
	renamed := 0
	for _, r := range all {
		key := r.vault + "\x00" + r.name
		if !seen[key] {
			seen[key] = true
			continue
		}
		short := r.id
		if len(short) > 8 {
			short = short[:8]
		}
		candidate := fmt.Sprintf("%s-%s", r.name, short)
		newName := candidate
		// Disambiguate if the short-id suffix still collides (e.g. two ids share a prefix,
		// or the renamed value matches a pre-existing name).
		for i := 1; seen[r.vault+"\x00"+newName]; i++ {
			newName = fmt.Sprintf("%s-%d", candidate, i)
		}
		if _, err := d.ExecContext(ctx,
			fmt.Sprintf("UPDATE %s SET name = ? WHERE id = ?", table), newName, r.id); err != nil {
			return renamed, fmt.Errorf("rename collision in %s: %w", table, err)
		}
		logrus.WithFields(logrus.Fields{
			"table": table, "id": r.id, "old_name": r.name, "new_name": newName,
		}).Warn("Renamed colliding resource during multi-vault migration")
		renamed++
		seen[r.vault+"\x00"+newName] = true
	}
	return renamed, nil
}
