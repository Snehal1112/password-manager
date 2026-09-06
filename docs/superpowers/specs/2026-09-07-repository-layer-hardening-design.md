# Repository Layer Hardening — Design

**Date:** 2026-09-07
**Branch:** `refactor/repo-hardening` (off `v-4.0.0`)
**Scope decision:** confirmed defects + shared helpers. No exported interface,
signature, or error-message changes.

## Background

`internal/repositories` holds 24 non-test Go files, 6,715 lines. It has already
been through three deduplication passes:

- **P1 scope refactor (2026-07)** — `ReadByOwner`/`ReadInVault`/`UpdateInVault`
  method pairs collapsed into a single `model.Scope` parameter, with
  `scope_predicate.go` turning the scope into a `WHERE` fragment.
- **Generic scoped CRUD (2026-08-17, extended 2026-08-24)** —
  `scoped_crud.go`'s `ScopedGet[T]`, `ScopedList[T]`, and `ScopedExec` now back
  the secret/key/certificate `Read`/`FindByName`/`Update`/`List` methods.
- **Table-driven item lifecycle (`207e285`)** — `item_lifecycle.go`'s
  `softDeleteItem`/`recoverItem`/`purgeItem`/`setPurgeProtectionItem` and the
  three vault-cascade functions, driven by a per-type `itemLifecycleConfig`.

Generic tag access already exists too, as `db.NewTagRepository[T]`.

**Consequence for this work:** the obvious generics opportunities are taken. A
fresh "introduce generics" pass would largely re-do finished work and churn the
three most security-critical repositories for no behavioral gain. What remains
is a set of concrete defects plus the duplication those earlier passes did not
reach. This design addresses exactly that.

## Findings

Severity is about consequence, not effort. Every item below was verified
against source at `HEAD`, not taken from the knowledge base (which is 94
commits stale and was used only to locate prior art).

### F1 — Swallowed scan errors truncate result sets silently

`rotation_repository.go` has three `for rows.Next()` loops (at lines 269, 318,
430) that respond to a failed `rows.Scan` with `log.Error(...)` followed by
`continue`, and never call `rows.Err()` afterwards. A driver failure partway
through iteration therefore returns a **short list with a nil error**. Callers
cannot tell a truncated rotation-policy listing from a complete one.

`session_repository.go`'s `GetActiveSessionsByUserID` (lines 239-241 and
246-250) has the same `continue` on both a scan failure and a `uuid.Parse`
failure. It does check `rows.Err()`, so it is the milder half of the pair, but
rows are still dropped silently — a user auditing where their account is signed
in can be shown fewer sessions than actually exist.

This is the identical pattern already fixed in `versioning_repository.go` by
commit `6cd6d52` ("no longer swallows scan errors"). These four sites were
missed by that fix.

**Severity: high.** Silent wrong answers, no error surfaced, security-visible
in the session case.

### F6 — Discarded `uuid.Parse` errors silently yield `uuid.Nil`

Thirty-six sites assign a parsed UUID while discarding the error:

```go
policy.ID, _ = uuid.Parse(id)
policy.UserID, _ = uuid.Parse(userID)
policy.VaultID, _ = uuid.Parse(vaultID)
```

Distribution: `rotation_repository.go` (21 sites, lines 125-127, 191-193,
286-287, 339-340, 450-453, 479-480, 529-531, 654-656),
`versioning_repository.go` (9 sites, lines 109-111, 146-148, 178-180), and
`certificate_policy_repository.go` (6 sites, lines 93-95, 191-193).

A malformed or empty UUID column therefore produces `uuid.Nil` rather than an
error. The fields affected are not incidental: `policy.UserID`,
`policy.VaultID`, and `p.UserID` all feed authorization-adjacent logic, and
`uuid.Nil` is a meaningful value elsewhere in this codebase — it is the
`auditActor` constant for key and certificate lifecycle operations, and
`model.NewAdminScope(uuid.Nil)` is a real, privileged scope. A silently
nil-valued `VaultID` is strictly worse than a returned error.

Every other scanner in the package (`scanKeyRow`, `scanCertificateRow`,
`scanSecretRow`, `parseRoleAssignmentIDs`) returns a wrapped parse error. These
three files are the outliers.

**Severity: medium-high.** Silent substitution of a privileged sentinel value
for corrupt data, in the same family as F1 but with a worse failure value.

### F2 — `CertificateRepository.ListAll` duplicates the SELECT list

`certificate_repository.go:704` is the second hand-written column list in the
file, parallel to the canonical `certificateColumns` const at line 65. It omits
`vault_id`, `deleted_at`, and `purge_protection`, and it scans with an inline
loop rather than the shared `scanCertificateRow`.

Two distinct problems:

1. **Live:** lines 723-726 use `uuid.MustParse` for `id`, `user_id`, and
   `key_id`. A malformed UUID in any of those columns **panics** the renewal
   scheduler's goroutine rather than returning an error. Every other scanner in
   the package returns a wrapped parse error.
2. **Latent:** `cert.VaultID` is left zero for every certificate the renewal
   scheduler sees. This is *not* currently exploitable —
   `CheckAndRenewCertificates` (`renewal_service.go:86`) passes
   `model.NewAdminScope(cert.UserID)`, which applies no vault predicate, so the
   zero value never reaches a query. It becomes a real bug the moment renewal
   grows any vault-aware behavior.

This duplicated-SELECT-list shape is the documented cause of an earlier bug in
which `keyColumns` and `certificateColumns` omitted `deleted_at`/
`purge_protection`, making every `List()` return both fields zero-valued.

**Severity: medium-high.** One live panic vector, one latent correctness trap,
and the structural cause of a bug this codebase has already been bitten by.

### F3 — Error-identity by string comparison

`role_assignment_repository.go:119` reads:

```go
if err.Error() == "role assignment not found" {
    return nil, nil
}
```

`FindByTuple`'s "no such assignment" contract rests entirely on that literal.
Rewording the message in `scanRoleAssignment` — a change nothing would flag as
risky — silently flips `FindByTuple` from returning `(nil, nil)` to returning an
error, changing an authorization-adjacent code path.

Several sites return a bare `fmt.Errorf("user not found")` without wrapping the
`ErrNotFound` sentinel that `errors.go` exists to provide. The consequential one
is `user_repository.go:333` (`ReadByExternalSubject`): OIDC's
`FindOrCreateExternalUser` needs to distinguish "no such external user, create
one" from "the database is broken", and cannot do so by `errors.Is`.

Three sites also compare with `err == sql.ErrNoRows` rather than
`errors.Is(err, sql.ErrNoRows)` — `access_policy_repository.go:198`,
`oauth2_client_repository.go:110`, and `role_assignment_repository.go:149`. This
works today only because nothing between the driver and those lines wraps the
error; any future wrapping breaks them silently.

**Severity: medium.** No current misbehavior; a sharp edge that converts an
innocuous edit into a behavior change.

### F4 — `executeWithMetrics` copy-pasted five times, ignoring configuration

Five definitions exist: `key_repository.go:280`, `certificate_repository.go:330`,
`secret_repository.go:125`, `user_repository.go:43`, `session_repository.go:434`.
Each hardcodes `100 * time.Millisecond` as the slow-query cutoff.

**Correction (2026-09-07, found during implementation):** an earlier draft of
this section called all five *identical*. That was wrong, and the difference
matters. Four are byte-identical apart from an optional `"table"` log field.
`SessionRepository`'s diverges in three ways:

1. It **never calls `db.RecordQueryExecution(duration)`** — so session
   operations have never been counted in `QueryCount`, `TotalQueryTime`, or
   `SlowQueryCount` at all. The database-performance metrics silently exclude
   an entire repository.
2. It logs through `r.logger` (the injected `*logging.Logger`) rather than the
   package-level `logrus` the other four use.
3. It emits a different message, `"Slow session repository query detected"`,
   plus a `"threshold": 100` field the others do not have — a field that
   hardcodes the very value this finding is about.

Consolidating therefore does more than remove duplication for session: it
starts counting session queries in the shared metrics for the first time. That
is the right outcome — session lookups are ordinary database queries and their
absence from `QueryCount` made the metric under-report — but it is a **behavior
change to a metric's meaning**, not a pure refactor, and operators reading
`rocketvault_db_*` will see the counts step up on deployment.

Two smaller consequences of the same consolidation: the distinct log message is
replaced by the shared `"Slow database query detected"` (so any log-based alert
matching the old string stops matching), and the `"threshold": 100` field is
dropped rather than corrected.

Meanwhile `db.RecordQueryExecution` — which every one of those five calls —
applies `getSlowQueryThreshold()`, the value `bootstrap.go:296` sets from
`monitoring.slow_query_threshold`. So once an operator tunes that setting, the
`SlowQueryCount` metric and the "Slow database query detected" log warnings
apply **different thresholds** and disagree about which queries were slow.

Related inconsistency: `SecretRepository.Update` and `SecretRepository.Delete`
are not wrapped in metrics at all, while their key and certificate equivalents
are.

**Severity: medium.** Observability that misleads under exactly the conditions
it was configured to help with.

### F5 — Tag rows orphaned on purge and on secret delete

`secret_tags`, `key_tags`, and `certificate_tags` each declare
`FOREIGN KEY (...) REFERENCES ... ON DELETE CASCADE` (`internal/db/db.go` lines
437-443, 479-485, 589-595). SQLite runs with the `foreign_keys` pragma **off**
project-wide — the codebase documents this in at least four places and it is
the stated reason `RoleAssignmentRepository.DeleteByVault`,
`AccessPolicyRepository.DeleteByVault`, and the webhook cleaner exist at all.

So the declared cascade never fires on SQLite, and:

- `item_lifecycle.go`'s `purgeItem` issues a bare
  `DELETE FROM <table> WHERE id = ?`, stranding every tag row of the purged
  item — for secrets, keys, **and** certificates.
- `purgeVaultContents` does the same vault-wide.
- `SecretRepository.Delete` (`secret_repository.go:369`) deletes the row without
  touching `secret_tags`. `KeyRepository.Delete` and
  `CertificateRepository.Delete` both delete their tag rows explicitly inside a
  transaction, which establishes the intended behavior.

Orphaned rows are unreachable through any route and are never swept, exactly
like the role-assignment rows whose cleaner already exists. Because tag primary
keys are `(item_id, tag)`, a purged-then-recreated item that reuses an ID would
also inherit the dead tags.

**Severity: medium.** Unbounded row growth and a stale-data path; not a
disclosure risk, since orphaned tags are only reachable by an item ID that no
longer resolves.

## Non-goals

Found during review, deliberately out of scope because each requires an
exported-interface change, which this effort excludes:

- Five dead stubs on `SecretRepositoryInterface` (`ExportSecrets`,
  `ImportSecrets`, `GetVersions`, `GetVersion`, `GetLatestVersion`) that return
  "moved to X service" errors and exist only to satisfy the interface.
- `SecretFilter.Tags` is accepted by `List` and silently ignored, while
  `KeyFilter.Tags` and `CertificateFilter.Tags` are honored.
- `SecretFilter` is still declared in `internal/repositories` while `KeyFilter`,
  `CertificateFilter`, and `AuditFilter` moved to `model/filters.go`.
- `SecretRepository.List` does not load tags; the key and certificate
  equivalents batch-load them.

These are recorded here so the next person does not have to rediscover them.

## Approach

Every change is either internal to a function body or a new **unexported**
helper in the `repositories` package. Nothing in `internal/repositories/mocks/`,
no service test double, and no caller signature changes.

### Error messages are extended, never replaced

Service-layer tests assert on error substrings, not sentinels — for example
`assert.Contains(t, err.Error(), "key not found")` in
`internal/services/keys/key_service_extended_test.go:600`, with more than a
dozen equivalents across the certificate, secret, and auth service test suites.

Therefore F3's fix **appends** to existing messages:

```go
// Before
return fmt.Errorf("user not found")
// After
return fmt.Errorf("user not found: %w", ErrNotFound)
```

The original text survives as a prefix, every `Contains` assertion still passes,
and `errors.Is` starts working. Rewriting a message is out of bounds.

### Shared metrics helper is package-level, not a struct field

`itemLifecycleConfig` is supplied by a `crud()` **method** rather than a
constructor-set field, because tests build these repositories via struct
literals — a stored field would zero-value there and the nil `wrap` would panic
on first call. The same hazard applies to any per-repository threshold field.

So F4's helper takes its threshold from a new exported
`db.SlowQueryThreshold()` accessor (wrapping the existing unexported
`getSlowQueryThreshold`), and is a package-level function:

```go
func withMetrics(table, operation string, fn func() error) error
```

No constructor changes, no new struct fields, struct-literal construction
unaffected.

### Tag cleanup and delete deduplication are one edit

F5's fix requires `itemLifecycleConfig` to learn the tag table and its foreign
key column. Once it knows those, `KeyRepository.Delete` and
`CertificateRepository.Delete` — which differ only in table names and log labels
— collapse into a shared `deleteItemWithTags`, and `SecretRepository.Delete`
gains the tag cleanup it is missing by adopting the same helper. Splitting the
fix from the deduplication would mean touching the same config twice.

`purgeItem` currently issues a bare `Exec`. Adding a second statement makes it
two writes that must succeed or fail together, so it moves inside a
transaction — using the `db.DBTX` executor it already receives when called
through a `...Tx` path, and opening its own only when handed a plain connection.

## Testing

Tasks that change behavior get a failing test first:

- **F1:** a repository test proving a truncated scan returns an error rather
  than a short slice.
- **F6:** a test proving a malformed UUID column returns a wrapped parse error
  rather than a `uuid.Nil`-valued struct.
- **F5:** a test proving tag rows are gone after purge, and after
  `SecretRepository.Delete`.

F2, F3, and F4 are refactors with no intended behavior change; existing coverage
plus the package's spec-lock tests carry them. F3 additionally gets an
`errors.Is` assertion at each newly-wrapped site.

**F6 is the one change that alters behavior on data that exists today.** If any
deployed database holds a malformed UUID in these columns, the affected read
starts returning an error where it previously returned a `uuid.Nil` field. That
is the correct behavior and the whole point of the fix, but it is a real
behavior change rather than a pure refactor, and its plan says so.

Per task, before its commit:

```
go build ./...
go vet ./...
go test ./internal/repositories/... ./internal/services/...
```

The `scope-gate` CI job must stay green — it greps for hand-built populated
`model.Scope{...}` literals and for legacy `InVault`/`ByOwner` method names.

## Delivery

Branch `refactor/repo-hardening` off `v-4.0.0`, one signed commit per task
(GPG key `61D246B30285ED35`), commits authored via the `1-git-commit` skill.

Work is split across six plans of at most three tasks each. Each plan names its
successor so the chain runs without prompting:

| Plan | Covers | Files | Behavior change | Next |
|------|--------|-------|-----------------|------|
| 01 | F1 + F6 in the rotation repository | `rotation_repository.go` | yes | 02 |
| 02 | F1 + F6 in the remaining repositories | `versioning_`, `certificate_policy_`, `session_` | yes | 03 |
| 03 | F2 — `ListAll` SELECT-list duplication | `certificate_repository.go` | no | 04 |
| 04 | F3 — `ErrNotFound` sentinels, `errors.Is` | `role_assignment_`, `user_`, `access_policy_`, `oauth2_client_` | no | 05 |
| 05 | F4 — shared `withMetrics` | 5 repositories + `internal/db` | no | 06 |
| 06 | F5 — tag orphans + shared delete | `item_lifecycle.go` + 3 repositories | yes | — (final) |

**Plans are split by file, not by finding.** F1 (swallowed scan errors) and F6
(discarded parse errors) occur in the *same loop bodies* — fixing one without
the other would mean editing the same six functions twice and reviewing the
same diff hunks twice. So plan 01 takes every error-swallowing site in
`rotation_repository.go` (which holds 21 of the 36 parse sites and 3 of the 4
scan-error sites) and plan 02 takes the rest.

Ordering rationale: the two error-surfacing plans run first, since they are the
highest-severity defects and both make previously-silent failures loud — better
to learn early if that shakes anything loose. The three pure refactors (03, 04,
05) sit in the middle, where a green test run is a meaningful signal precisely
because nothing should change. Plan 06 is last because it is the largest edit
and the only one restructuring a shared helper all three item repositories
depend on; sequencing it last means a failure there cannot obscure the five
fixes before it.

Plans 03, 04, and 05 are mutually independent and may be reordered. Plans 01,
02, and 06 each stand alone. No plan depends on a later plan's output, and no
two plans modify the same function.
