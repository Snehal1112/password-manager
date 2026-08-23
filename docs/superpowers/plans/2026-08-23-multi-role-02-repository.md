# Multi-Role: Repository Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `model.User.Role string` with `model.User.Roles []string`,
and make `UserRepository` read/write the new `user_roles` table transactionally.

**Architecture:** `model.User.Roles []string` becomes the one source of truth
Go code reads. `UserRepository.Create`/`Update` gain a transactional
"replace the full role set" step (delete-all-then-insert-all against
`user_roles`, matching the design's locked semantics). `Read`/`ReadByUsername`/
`ReadByExternalSubject`/`List` each gain a second query to populate `Roles`.
`users.role` is still written (comma-joined, for defense-in-depth during
rollout) but never read by this new code.

**Tech Stack:** Go, `database/sql`, existing `internal/repositories` patterns.

**Spec:** `docs/superpowers/specs/2026-08-23-multi-role-user-assignment-design.md`

## Global Constraints

- Depends on Plan `2026-08-23-multi-role-01-db-schema.md` (the `user_roles`
  table must exist) — do not start this plan before that one is merged.
- `model.User.Roles []string` — exact field name, replaces `Role string` at
  `model/user.go:18`.
- Role-set replace must be transactional (`Create`/`Update` are NOT
  transactional today except `Delete` — this plan adds transactions to both).
- `user_roles` rows cascade-delete via the existing `ON DELETE CASCADE` FK —
  do not add manual cleanup in `UserRepository.Delete`.

---

### Task 1: `model.User.Roles` + transactional role-set-replace helper

**Files:**
- Modify: `model/user.go:12-26` (the `User` struct)
- Modify: `internal/repositories/user_repository.go` (add two new private
  methods: `replaceUserRoles` and `fetchUserRoles`)
- Test: `internal/repositories/missing_coverage_test.go` (existing file, add
  new test functions at the end)

**Interfaces:**
- Produces:
  - `model.User.Roles []string` (field, JSON tag `json:"roles"`)
  - `(r *UserRepository) replaceUserRoles(ctx context.Context, tx *sql.Tx, userID uuid.UUID, roles []string) error`
  - `(r *UserRepository) fetchUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error)`
- Consumes: the `user_roles` table (Plan 01, Task 1).

- [ ] **Step 1: Write the failing test**

`setupUserDB(t)` in this file hand-rolls its own `CREATE TABLE users (...)`
schema, independent of `internal/db/db.go`'s real `createOptimizedSchema()`/
`migrateSchema()` (Plan 01 doesn't touch this test helper). Add the
`user_roles` table to it now, or every test below fails with `no such table:
user_roles` regardless of the repository code:

```go
		CREATE TABLE IF NOT EXISTS user_roles (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			role       TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (user_id, role),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);
```

Add this right after `setupUserDB`'s existing `CREATE TABLE users (...)`
block, inside the same `db.Exec(...)` call.

Also update `newUser(username, role string)` — Step 3 below changes
`model.User.Role` to `Roles`, so change `newUser`'s body from `Role: role` to
`Roles: []string{role}` in the same pass:

```go
func TestUserRepository_Create_WritesMultipleRoles(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	u := &model.User{
		ID:           uuid.New(),
		Username:     "dave",
		PasswordHash: "hashed-password",
		Roles:        []string{"admin", "secrets_manager"},
		CreatedAt:    time.Now(),
	}
	require.NoError(t, repo.Create(ctx, u))

	got, err := repo.Read(ctx, u.ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"admin", "secrets_manager"}, got.Roles)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/... -run TestUserRepository_Create_WritesMultipleRoles -v`
Expected: FAIL — `model.User` has no field `Roles` (compile error)

- [ ] **Step 3: Change `model.User`**

In `model/user.go`, change:

```go
	Role         string    `json:"role"`
```

to:

```go
	Roles        []string  `json:"roles"`
```

(keep every other field in the `User` struct exactly as-is — `ID`, `Username`,
`PasswordHash`, `TOTPSecret`, `AuthProvider`, `ExternalIDPSubject`, `CreatedAt`).

- [ ] **Step 4: Add the transactional helpers to `UserRepository`**

In `internal/repositories/user_repository.go`, add (near the bottom of the
file, after `Delete`):

```go
// replaceUserRoles deletes every existing user_roles row for userID and
// inserts one row per entry in roles, inside the given transaction. Empty
// or duplicate role strings are silently skipped -- callers are expected to
// have already validated the role names themselves (this repository does
// not know the valid-roles allowlist).
func (r *UserRepository) replaceUserRoles(ctx context.Context, tx *sql.Tx, userID uuid.UUID, roles []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id = ?`, userID.String()); err != nil {
		return fmt.Errorf("delete existing user_roles: %w", err)
	}
	seen := map[string]bool{}
	for _, role := range roles {
		if role == "" || seen[role] {
			continue
		}
		seen[role] = true
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO user_roles (id, user_id, role) VALUES (?, ?, ?)`,
			uuid.New().String(), userID.String(), role,
		); err != nil {
			return fmt.Errorf("insert user_roles row (role=%s): %w", role, err)
		}
	}
	return nil
}

// fetchUserRoles returns every role currently assigned to userID, in no
// particular order.
func (r *UserRepository) fetchUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT role FROM user_roles WHERE user_id = ?`, userID.String())
	if err != nil {
		return nil, fmt.Errorf("query user_roles: %w", err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("scan user_roles row: %w", err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate user_roles: %w", err)
	}
	return roles, nil
}
```

Check `r.db`'s type in this file (it's the `db.DB` wrapper used throughout —
confirm `QueryContext`/`ExecContext` are the right method names by checking
an existing method like `ReadByUsername` in the same file).

- [ ] **Step 5: Wire `Create` to use the helper (now transactional)**

`Create` is currently not transactional. Rewrite it to wrap the
username-uniqueness-check + INSERT + role-replace in one transaction:

```go
func (r *UserRepository) Create(ctx context.Context, user *model.User) error {
	logrus.WithFields(logrus.Fields{
		"username": user.Username,
		"roles":    user.Roles,
		"user_id":  user.ID.String(),
	}).Debug("Inserting user into database")

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var existingUserID string
	err = tx.QueryRowContext(ctx, "SELECT id FROM users WHERE username = ?", user.Username).Scan(&existingUserID)
	if err == nil {
		r.log.LogAuditError(user.ID.String(), "create_user", "failed", "Username already exists", nil)
		return fmt.Errorf("username already exists")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		r.log.LogAuditError(user.ID.String(), "create_user", "failed", "Failed to check existing username", err)
		return fmt.Errorf("failed to check existing username: %w", err)
	}

	authProvider := user.AuthProvider
	if authProvider == "" {
		authProvider = model.AuthProviderLocal
	}
	var externalSubject any
	if user.ExternalIDPSubject != "" {
		externalSubject = user.ExternalIDPSubject
	}
	// users.role kept in sync (comma-joined) as a legacy/defense-in-depth
	// copy -- not read by any new code, see the design spec.
	_, err = tx.ExecContext(
		ctx,
		"INSERT INTO users (id, username, password_hash, totp_secret, role, auth_provider, external_idp_subject, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		user.ID.String(), user.Username, user.PasswordHash, user.TOTPSecret, strings.Join(user.Roles, ","), authProvider, externalSubject, user.CreatedAt,
	)
	if err != nil {
		r.log.LogAuditError(user.ID.String(), "create_user", "failed", "Failed to insert user", err)
		return fmt.Errorf("failed to insert user: %w", err)
	}

	if err := r.replaceUserRoles(ctx, tx, user.ID, user.Roles); err != nil {
		r.log.LogAuditError(user.ID.String(), "create_user", "failed", "Failed to insert user_roles", err)
		return fmt.Errorf("failed to insert user_roles: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit user create: %w", err)
	}

	r.log.LogAuditInfo(user.ID.String(), "create_user", "success", fmt.Sprintf("User inserted: %s", user.Username))
	return nil
}
```

Add `"strings"` to the file's imports if not already present.

- [ ] **Step 6: Wire `Update` the same way**

Rewrite `Update` similarly — wrap the `UPDATE users` + `replaceUserRoles` in
one transaction:

```go
func (r *UserRepository) Update(ctx context.Context, user *model.User) error {
	logrus.WithFields(logrus.Fields{
		"user_id":  user.ID.String(),
		"username": user.Username,
	}).Debug("Updating user in database")

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	result, err := tx.ExecContext(
		ctx,
		"UPDATE users SET username = ?, password_hash = ?, role = ? WHERE id = ?",
		user.Username, user.PasswordHash, strings.Join(user.Roles, ","), user.ID.String(),
	)
	if err != nil {
		r.log.LogAuditError(user.ID.String(), "update_user", "failed", "Failed to update user", err)
		return fmt.Errorf("failed to update user: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		r.log.LogAuditError(user.ID.String(), "update_user", "failed", "User not found for update", nil)
		return fmt.Errorf("user not found")
	}

	if err := r.replaceUserRoles(ctx, tx, user.ID, user.Roles); err != nil {
		r.log.LogAuditError(user.ID.String(), "update_user", "failed", "Failed to replace user_roles", err)
		return fmt.Errorf("failed to replace user_roles: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit user update: %w", err)
	}

	r.log.LogAuditInfo(user.ID.String(), "update_user", "success", fmt.Sprintf("User updated: %s", user.Username))
	return nil
}
```

- [ ] **Step 7: Run test to verify it passes**

Run: `go test ./internal/repositories/... -run TestUserRepository_Create_WritesMultipleRoles -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add model/user.go internal/repositories/user_repository.go internal/repositories/missing_coverage_test.go
git commit -m "feat(repositories): make UserRepository.Create/Update write user_roles transactionally"
```

---

### Task 2: Populate `Roles` on every read path

**Files:**
- Modify: `internal/repositories/user_repository.go` — `Read`, `ReadByUsername`,
  `ReadByExternalSubject`, `List`
- Test: `internal/repositories/missing_coverage_test.go`

**Interfaces:**
- Consumes: `fetchUserRoles` from Task 1.
- Produces: every read method returns a `model.User`/`[]model.User` with
  `Roles` correctly populated.

- [ ] **Step 1: Write the failing test**

```go
func TestUserRepository_ReadPaths_PopulateRoles(t *testing.T) {
	t.Parallel()
	db := setupUserDB(t)
	repo := repositories.NewUserRepository(rvdb.NewConn(db, rvdb.SQLite), newLogger())
	ctx := context.Background()

	u := &model.User{
		ID:           uuid.New(),
		Username:     "erin",
		PasswordHash: "hashed-password",
		Roles:        []string{"crypto_manager", "certificate_manager"},
		CreatedAt:    time.Now(),
	}
	require.NoError(t, repo.Create(ctx, u))

	byID, err := repo.Read(ctx, u.ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, u.Roles, byID.Roles, "Read")

	byUsername, err := repo.ReadByUsername(ctx, "erin")
	require.NoError(t, err)
	assert.ElementsMatch(t, u.Roles, byUsername.Roles, "ReadByUsername")

	list, err := repo.List(ctx)
	require.NoError(t, err)
	var found bool
	for _, lu := range list {
		if lu.ID == u.ID {
			found = true
			assert.ElementsMatch(t, u.Roles, lu.Roles, "List")
		}
	}
	require.True(t, found, "created user must appear in List")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repositories/... -run TestUserRepository_ReadPaths_PopulateRoles -v`
Expected: FAIL — `Roles` empty on every returned user (still only scanning the
legacy `role` column, and `model.User.Roles` isn't wired up to it)

- [ ] **Step 3: Update `Read`**

```go
func (r *UserRepository) Read(ctx context.Context, id uuid.UUID) (*model.User, error) {
	var user model.User
	var idStr string
	var legacyRole string
	var externalSubject sql.NullString

	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, username, password_hash, totp_secret, role, auth_provider, external_idp_subject, created_at FROM users WHERE id = ?",
		id.String(),
	).Scan(&idStr, &user.Username, &user.PasswordHash, &user.TOTPSecret, &legacyRole, &user.AuthProvider, &externalSubject, &user.CreatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %w", err)
	}
	user.ExternalIDPSubject = externalSubject.String

	user.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user ID: %w", err)
	}

	roles, err := r.fetchUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user roles: %w", err)
	}
	user.Roles = roles

	return &user, nil
}
```

`legacyRole` is scanned and discarded — it's still a column in the row, must
be scanned into something, but nothing downstream reads it.

- [ ] **Step 4: Update `ReadByUsername` and `ReadByExternalSubject` the same way**

Both follow the identical shape: keep the same `SELECT ... role ...` query,
scan `role` into a discarded `legacyRole` variable, then call
`r.fetchUserRoles(ctx, user.ID)` and assign to `user.Roles` before returning.
Apply the same three-line addition (`legacyRole` scan target, `fetchUserRoles`
call, `user.Roles = roles`) to both.

- [ ] **Step 5: Update `List`**

`List` returns `[]model.User` — after building the slice from the row scan
(same "scan role into a discarded variable" change as above), loop over the
slice once more to populate each entry's `Roles`:

```go
	for i := range users {
		roles, err := r.fetchUserRoles(ctx, users[i].ID)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch roles for user %s: %w", users[i].ID, err)
		}
		users[i].Roles = roles
	}
```

Add this loop right before `List`'s final `return users, nil`.

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./internal/repositories/... -run TestUserRepository_ReadPaths_PopulateRoles -v`
Expected: PASS

- [ ] **Step 7: Run the full repository test suite**

Run: `go test ./internal/repositories/... -v`
Expected: all PASS — this touches shared helpers (`newUser`, `setupUserDB`),
so check for compile errors in every test file under this package, not just
the ones this plan wrote.

- [ ] **Step 8: Commit**

```bash
git add internal/repositories/user_repository.go internal/repositories/missing_coverage_test.go
git commit -m "feat(repositories): populate Roles on all UserRepository read paths"
```
