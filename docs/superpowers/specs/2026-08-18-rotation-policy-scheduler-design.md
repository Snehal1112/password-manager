# Rotation-Policy Scheduler — Design

**Roadmap item:** "Rotation-policy scheduler — actually execute the rotation
policies that already exist (CRUD-only today); currently a silent no-op that
could give a false sense of security." (`.claude/roadmap-azure-parity-and-beyond.md`,
Phase 1, highest priority.)

**Predecessor:** `docs/superpowers/specs/2026-08-17-vault-scope-rotation-policies-design.md`
(Spec A — vault-scoped the two rotation-policy tables for authorization. Already
implemented and merged, commit `e246e3a`.) This spec (Spec B) is independent of
Spec A's authorization work; it builds on the `vault_id` columns Spec A added
but does not change how they're used for access control.

## 1. Goal

Today, three resource types have a rotation-policy *concept*, but only two
have anything that executes it:

| Resource | Policy storage | Executes automatically? |
|---|---|---|
| Secrets | `rotation_policies` + `secret_policies` | Yes — `internal/services/secrets/scheduler_service.go`, hand-rolled ticker |
| Certificates | `AutoRenew`/`RenewalDays` fields on `certificates` | Yes — `internal/services/certificates/renewal_scheduler.go`, hand-rolled ticker |
| Keys | `key_rotation_policies` (1:1 with a key) | **No.** `PUT /keys/{id}/rotationpolicy` stores the row; nothing ever reads it on a schedule. `RotateKey` only runs when a human calls the CLI or API directly. |

This spec closes the keys gap and, while doing so, removes the duplication
between the two schedulers that already work by extracting their shared
ticker/lifecycle logic into one generic core.

**In scope:**
- A generic scheduler core, `internal/schedulerkit`, mirroring the existing
  `cachekit` generic-core-plus-thin-wrapper pattern.
- A new key-rotation executor that actually calls `RotateKey` on a schedule.
- Migrating the secrets and certificate schedulers onto `schedulerkit`
  (internal plumbing only — their public types/constructors are unchanged).
- One unified `rotation:` YAML config section covering all three resource
  types' enabled/interval settings — replacing values that are currently
  hardcoded in `bootstrap.go`/`app.go` and not configurable at all.

**Out of scope:** see §11.

## 2. Decisions

Resolved during brainstorming, recorded here so the plan doesn't re-litigate them:

1. **Due-date baseline storage:** new columns on `key_rotation_policies`
   itself (not on `keys`, not computed on the fly from `key_versions`). See §4.
2. **Sweep model:** a single global admin-scoped sweep per tick (mirrors the
   certificate renewal scheduler), not per-user iteration (which the secrets
   scheduler uses only because it also handles per-user *reminders* — keys have
   no reminder feature to iterate for).
3. **Migration scope:** full unification now. All three schedulers move onto
   `schedulerkit` in this spec, not just the new key executor.
4. **Vault-scoping:** the scheduler sweep is intentionally vault-agnostic
   (`model.NewAdminScope`), matching the secrets scheduler's existing
   `performAutomaticRotation` (`model.NewAdminScope(uuid.Nil)` at
   `scheduler_service.go:251`). See §10 for the full rationale — this was
   discussed explicitly and is not an oversight.

## 3. Architecture — `internal/schedulerkit`

New package, generic ticker/lifecycle core:

```go
package schedulerkit

type Runner struct {
	name     string
	checkFn  func(ctx context.Context) error
	log      *logging.Logger
	ticker   *time.Ticker
	stopChan chan struct{}
	wg       sync.WaitGroup
	mu       sync.RWMutex
	running  bool
}

func NewRunner(name string, checkFn func(ctx context.Context) error, log *logging.Logger) *Runner

// Start begins the ticker loop. Runs checkFn once immediately, then once per
// interval. Returns an error if already running.
func (r *Runner) Start(ctx context.Context, interval time.Duration) error

// Stop signals the loop to exit and waits for the in-flight tick (if any) to finish.
func (r *Runner) Stop() error

func (r *Runner) IsRunning() bool
```

Behavior contract (this is the union of what the two existing schedulers do
today, standardized):
- Runs `checkFn` once immediately on `Start`, then on every tick thereafter —
  matches `CertificateRenewalScheduler.run()` today. This is a small behavior
  change for secrets, which currently waits for the first tick before doing
  anything; see §9 for why this is treated as a fix, not a regression.
- A `checkFn` error is logged by the caller (schedulerkit does not swallow or
  interpret errors — it just logs `"scheduler tick failed"` with the error and
  continues to the next tick). Domain-specific per-item error handling (e.g.
  "one bad key shouldn't stop the sweep") stays inside each domain's `checkFn`,
  same as today.
- `Stop()` is graceful — waits for any in-flight `checkFn` call to return
  before returning, via the same `sync.WaitGroup` pattern the secrets
  scheduler already uses.

`schedulerkit` has no knowledge of secrets, certs, or keys — it takes a
callback and runs it on a schedule. Each domain's existing scheduler type
becomes a thin wrapper that owns its `checkFn` and delegates lifecycle calls
to an internal `*schedulerkit.Runner`.

## 4. DB migration — `key_rotation_policies` due-tracking

Mirrors `secret_policies`' existing `last_rotated_at`/`next_rotation_at`
pattern exactly, so the due-query stays a trivial `<= ?` comparison instead of
dialect-specific date arithmetic (matching `GetDueRotations`'s existing
`WHERE rp.enabled = TRUE AND sp.next_rotation_at <= ?`, `time.Now()` bound as
a parameter — see `internal/repositories/rotation_repository.go:490-506`).

New columns on `key_rotation_policies`:
- `last_rotated_at TIMESTAMP NULL` — when this policy last caused an
  automatic rotation. Null means "never auto-rotated by this policy."
- `next_rotation_at TIMESTAMP NOT NULL` — materialized due-date, computed in
  Go as `COALESCE(last_rotated_at, key.created_at) + rotate_after_days days`
  whenever the policy is upserted, and recomputed the same way immediately
  after each successful automatic rotation.

`createOptimizedSchema` gets both columns on table creation.
`migrateSchema` gets the dual-write `ALTER TABLE` pair plus a one-time
backfill (mirrors the `ALTER TABLE ... ADD COLUMN ... DEFAULT` +
backfill-`UPDATE` pattern Spec A already used for `vault_id`).

**Backfill anchors on migration time (`now`), not `key.created_at`.** Using
`key.created_at` here would retroactively mark every existing enabled policy
whose key predates its own rotation window as simultaneously overdue the
moment this feature ships — a thundering-herd mass rotation with no admin
having asked for it at that moment (the same class of bug Spec A's final
review caught with its cross-vault backfill). Existing policies instead start
their rotation clock fresh from the migration's run time:

```sql
ALTER TABLE key_rotation_policies ADD COLUMN last_rotated_at TIMESTAMP;
ALTER TABLE key_rotation_policies ADD COLUMN next_rotation_at TIMESTAMP;
UPDATE key_rotation_policies
SET next_rotation_at = datetime(?, '+' || rotate_after_days || ' days')
WHERE next_rotation_at IS NULL;
```
bound with a single `now := time.Now().UTC()` parameter computed once in Go
before the statement runs (not `datetime('now', ...)`, so a slow migration
doesn't skew individual rows against each other). The plan must supply the
equivalent Postgres form (`$1::timestamp + (rotate_after_days || ' days')::interval`,
same bound parameter) guarded the same way the rest of `migrateSchema`
branches on dialect.

This backfill rule is migration-only. `Upsert`'s ongoing runtime logic (new
policies created after migration, via the API) still anchors on
`key.created_at` when `last_rotated_at` is null — that's Azure-parity-correct
and reflects a single admin's deliberate choice on a specific key, not a mass
retroactive event.

`model.KeyRotationPolicy` gains `LastRotatedAt *time.Time` and
`NextRotationAt time.Time` fields.

## 5. Repository layer — `key_rotation_policy_repository.go`

Two additions to `KeyRotationPolicyRepositoryInterface`:

```go
// GetDuePolicies returns enabled policies whose next_rotation_at has passed,
// authorized by scope. Callers pass model.NewAdminScope for the scheduler
// sweep (see §10).
GetDuePolicies(ctx context.Context, scope model.Scope) ([]model.KeyRotationPolicy, error)

// MarkRotated stamps last_rotated_at and recomputes next_rotation_at after a
// successful automatic rotation.
MarkRotated(ctx context.Context, keyID uuid.UUID, scope model.Scope, at time.Time) error
```

`GetDuePolicies` query shape (parallels `GetDueRotations`):

```sql
SELECT id, key_id, user_id, vault_id, rotate_after_days,
       notify_before_expiry_days, expiry_days, enabled,
       last_rotated_at, next_rotation_at, created_at, updated_at
FROM key_rotation_policies
WHERE enabled = TRUE AND rotate_after_days > 0 AND next_rotation_at <= ?
```
(`rotate_after_days > 0` guards against a policy that only configures
`notify_before_expiry_days`/`expiry_days` with no rotation action — those
exist per Azure parity but must never fire `RotateKey`.) Built through
`ScopedList` exactly as `GetDueRotations` is, so `GetDuePolicies` also works
correctly if ever called with a non-admin scope (it won't be, today, but the
generic helper doesn't special-case that).

`Upsert` is extended to compute and persist `next_rotation_at` on every
create/update, using the key's `created_at` (fetched via a join or a
secondary read — implementation detail for the plan) when `last_rotated_at`
is still null.

## 6. Service layer

### 6.1 Key rotation executor (new)

New file, `internal/services/keys/rotation_executor.go`:

```go
type RotationExecutor struct {
	keyService KeyService
	policyRepo repositories.KeyRotationPolicyRepositoryInterface
	log        *logging.Logger
}

func NewRotationExecutor(keyService KeyService, policyRepo repositories.KeyRotationPolicyRepositoryInterface, log *logging.Logger) *RotationExecutor

// Check is the schedulerkit checkFn: sweep due policies and rotate.
func (e *RotationExecutor) Check(ctx context.Context) error {
	due, err := e.policyRepo.GetDuePolicies(ctx, model.NewAdminScope(uuid.Nil))
	if err != nil {
		return fmt.Errorf("get due key rotation policies: %w", err)
	}
	for _, policy := range due {
		if _, err := e.keyService.RotateKey(ctx, policy.KeyID, model.NewAdminScope(uuid.Nil)); err != nil {
			e.log.WithError(err).WithField("key_id", policy.KeyID).
				Error("automatic key rotation failed")
			continue // one bad key must not stop the sweep
		}
		if err := e.policyRepo.MarkRotated(ctx, policy.KeyID, model.NewAdminScope(uuid.Nil), time.Now()); err != nil {
			e.log.WithError(err).WithField("key_id", policy.KeyID).
				Error("failed to record key rotation timestamp")
			// Rotation already succeeded — do not retry the rotation itself
			// next tick just because the bookkeeping write failed. Logged so
			// it's visible, not retried, to avoid double-rotating.
		}
	}
	return nil
}
```

`RotateKey` already performs its own audit logging (`LogAuditInfo`/
`LogAuditError`, `internal/services/keys/key_service.go:759-760`) — the
executor adds no separate audit trail, matching how `performAutomaticRotation`
relies on the secret-rotation path's own audit calls rather than duplicating
them.

A thin `KeyRotationScheduler` wrapper (parallel to
`CertificateRenewalScheduler`) owns a `*schedulerkit.Runner` constructed with
`executor.Check` as the `checkFn`, and exposes `Start(ctx, interval)`/`Stop()`
for `bootstrap.go` to call.

### 6.2 Migrate secrets scheduler

`schedulerService` keeps its existing `SchedulerServiceInterface` and all
public methods (`ProcessUserRotations`, `ProcessUserReminders`,
`PerformManualRotation` stay directly callable — API/CLI manual-rotation
paths depend on them). Internally, `Start`/`Stop`/`IsRunning`/the `run()`
goroutine are deleted and replaced with a `*schedulerkit.Runner` whose
`checkFn` is `processAllUserOperations`. No behavior change other than the
"runs once immediately" standardization noted in §3/§9.

### 6.3 Migrate certificate scheduler

`CertificateRenewalScheduler` keeps its existing type, constructor signature,
and `Start(ctx)`/`Stop()` methods (referenced directly by `bootstrap.go` and
`bootstrap_test.go`). Internally, `run()`/its own ticker/`done` channel are
replaced with a `*schedulerkit.Runner` whose `checkFn` wraps
`svc.CheckAndRenewCertificates`.

## 7. Config — unified `rotation:` YAML section

New `config.RotationConfig`/`config.LoadRotationConfig()` in `config/config.go`,
following the exact pattern of `LoadMonitoringConfig` (§ `config/config.go:49-66`):

```go
type ResourceRotationConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	Interval time.Duration `mapstructure:"interval"`
}

type RotationConfig struct {
	Secrets      ResourceRotationConfig `mapstructure:"secrets"`
	Certificates ResourceRotationConfig `mapstructure:"certificates"`
	Keys         ResourceRotationConfig `mapstructure:"keys"`
}

func LoadRotationConfig() RotationConfig {
	cfg := RotationConfig{
		Secrets:      ResourceRotationConfig{Enabled: true, Interval: time.Hour},
		Certificates: ResourceRotationConfig{Enabled: true, Interval: 24 * time.Hour},
		Keys:         ResourceRotationConfig{Enabled: true, Interval: time.Hour},
	}
	// viper.IsSet guards per field, same style as LoadMonitoringConfig.
	...
	return cfg
}
```

`.rocketvault.yaml.example` gains:

```yaml
rotation:
  secrets:
    enabled: true
    interval: "1h"
  certificates:
    enabled: true
    interval: "24h"
  keys:
    enabled: true
    interval: "1h"
```

Defaults exactly match today's hardcoded values (`1h` for secrets — `app.go`'s
existing default; `24h` for certs — `bootstrap.go:327`'s existing literal), so
a config with no `rotation:` section at all behaves identically to today. This
is the first time any of the three intervals become configurable — today
they're compiled-in.

## 8. Bootstrap wiring (`bootstrap/bootstrap.go`)

- Replace `app.WithSchedulerEnabled(true, 1*time.Hour)` (line 403) with
  `app.WithSchedulerEnabled(rotationCfg.Secrets.Enabled, rotationCfg.Secrets.Interval)`.
- Replace `certServices.NewCertificateRenewalScheduler(sc, b.cfg.Logger, 24*time.Hour)`
  (line 327) with the config-driven interval, and skip `Start` entirely when
  `rotationCfg.Certificates.Enabled` is false (today it's unconditional).
- Add a new `keyRotationScheduler *keysServices.KeyRotationScheduler` field,
  constructed and started the same way `renewalScheduler` is
  (lines ~310-328), gated on `rotationCfg.Keys.Enabled`, and stopped in
  `Shutdown` alongside the other three (lines 433-444).

## 9. Testing

- `internal/schedulerkit`: unit tests for `Start`/`Stop`/`IsRunning`,
  immediate-first-run behavior, tick-triggers-checkFn, `Stop` waits for an
  in-flight tick, double-`Start` errors, `checkFn` error is logged and does
  not stop the loop. No dependency on any domain package.
- `internal/db`: migration test extending the pattern from
  `internal/db/rotation_vault_scope_migration_test.go` — proves
  `last_rotated_at`/`next_rotation_at` land on an old-shape DB, backfill is
  correct for a policy with no prior rotation, and a second migration run is
  idempotent.
- `internal/repositories/key_rotation_policy_repository_test.go`:
  `GetDuePolicies` returns only enabled + due + `rotate_after_days > 0` rows;
  `MarkRotated` updates both timestamp columns correctly.
- `internal/services/keys/rotation_executor_test.go`: due policy triggers
  `RotateKey`; a `RotateKey` failure is logged and does not abort the sweep
  or stop subsequent policies from processing; `MarkRotated` failure after a
  successful rotation is logged, not treated as a rotation failure.
- Secrets/cert scheduler migration: existing test suites for both
  (`scheduler_service_test.go`, cert scheduler tests) must continue to pass
  unmodified in terms of public-API behavior — internal delegation to
  `schedulerkit.Runner` is a refactor, not a contract change, aside from the
  documented immediate-first-run change (§3/§9 note) — add one new secrets
  scheduler test asserting the first check runs immediately on `Start`,
  not after the first tick.
- `bootstrap_test.go`: extend the existing `TestShutdown_With*Scheduler_StopsCleanly`
  pattern with a `TestShutdown_WithKeyRotationScheduler_StopsCleanly` case.

## 10. Vault-scoping — why the sweep is global

Discussed explicitly during brainstorming; recorded here so a future reader
doesn't mistake it for an oversight.

The scheduler is a trusted internal background process, not a user-initiated
request — it must see every vault's due policies on every sweep, or a policy
configured in one vault would silently never fire depending on which vault
happened to be in scope. `model.NewAdminScope` carries no vault predicate at
all (`model/scope.go:51-56`, "for trusted internal callers only"), which is
exactly what's needed here, and exactly what the secrets scheduler's own
`performAutomaticRotation` already does today for its policy lookups.

`key_rotation_policies.vault_id` (added by Spec A) continues to gate
user-facing access — the CLI's `PUT`/`GET`/`DELETE .../rotationpolicy` paths
and any future CLI equivalent still authorize through
`vaultcli.RequireDataAction` per-vault, unaffected by this spec. This spec
only changes what happens *after* a policy is already configured and enabled.

A key's own `vault_id` is never at risk during automatic rotation: `RotateKey`
reads the existing key row first (which carries its real `vault_id`) and
writes back to that same row — the admin scope affects only the authorization
predicate used for the read/write, not which vault the key belongs to.

The `rotation.keys.enabled`/`interval` config toggle (§7) is a single
deployment-wide switch, with no per-vault variant — consistent with the
existing purge and certificate-renewal schedulers, which are also global.
A vault admin who wants no auto-rotation for a specific key already has the
mechanism for that: leave `KeyRotationPolicy.Enabled = false` on that key.

## 11. Out of scope

- **Reminder/notification for upcoming key rotations or expiring key
  versions** (`notify_before_expiry_days`) — this spec only wires up the
  rotation action (`rotate_after_days`). A notification delivery mechanism
  does not exist for keys today (secrets' reminder system is email/webhook-less
  too, per the roadmap's Phase 3 "native webhook/notification system for
  rotation failures, expiry warnings" item) and building one is a separate,
  larger effort.
- **`expiry_days`** (how long each new key version stays valid) — this is
  about key-version lifetime/expiry enforcement, a distinct concern from
  triggering rotation, and is not touched by this spec.
- **Per-vault rotation config overrides** — see §10.
- **CLI command for key rotation policies** — none exists today
  (HTTP-API-only); adding one is orthogonal to making the policy actually
  execute, and is not part of this spec.
- **Retry/backoff for a failed automatic rotation** — a failed rotation is
  logged and picked up again on the *next* full interval tick (e.g., up to an
  hour later with the default config), not retried within the same tick.
  Matches the existing secrets/cert scheduler behavior; no new retry
  mechanism is introduced.

## 12. References

- Roadmap item: `.claude/roadmap-azure-parity-and-beyond.md`, Phase 1.
- Spec A (predecessor): `docs/superpowers/specs/2026-08-17-vault-scope-rotation-policies-design.md`
- Existing secrets scheduler: `internal/services/secrets/scheduler_service.go`
- Existing cert scheduler: `internal/services/certificates/renewal_scheduler.go`
- Existing generic-core precedent: `internal/cachekit/`
- Existing config-loader precedent: `config.LoadMonitoringConfig` (`config/config.go:49-66`)
- Existing due-query precedent: `rotationPolicyRepository.GetDueRotations` (`internal/repositories/rotation_repository.go:490-506`)
