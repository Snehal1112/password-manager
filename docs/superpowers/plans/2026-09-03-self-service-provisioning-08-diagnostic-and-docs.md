# Startup Diagnostic and Documentation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Log which principals hold a global `vaults:manage` policy, so release 2's breaking narrowing can be sized from real deployments — then document the feature.

**Architecture:** A read-only diagnostic in `migrateSchema` that warns and never fails, modeled on `warnMismatchedRotationPolicyVaults`. This is the whole reason release 1 and release 2 are separate: the diagnostic must run in the field before the behaviour it reports on is changed.

**Tech Stack:** Go 1.24, testify.

**Spec:** `docs/superpowers/specs/2026-09-03-self-service-vault-provisioning-design.md` §9

**Depends on:** `…-07-cli-surface.md`. This is the last plan of release 1.

## Global Constraints

- The diagnostic **must never fail startup**. A query error on a partially-built schema is expected and harmless; log at warn level and swallow, exactly as `warnMismatchedRotationPolicyVaults` does (`internal/db/db.go:1119-1130`).
- Release 1 ends here. **Do not implement `CheckVaultScopedAccess` or narrow `CanManageVault`/`CanManageRoleAssignments` in this plan** — that is release 2, and shipping it before this diagnostic has reported defeats the sequencing.
- `.claude/manual-testing-plan.md` and `.claude/roadmap-azure-parity-and-beyond.md` are **gitignored and untracked** (`.gitignore:127` ignores `.claude/` wholesale; only a handful of files were force-added). Edit them, but do not expect them in `git status` — and do not `git add -f` without asking.
- All commits are GPG-signed (`git commit -S`).

---

### Task 1: Global-grant diagnostic

**Files:**
- Modify: `internal/db/db.go` (new `warnGlobalVaultManageGrants`, called from `migrateSchema` beside `warnMismatchedRotationPolicyVaults` at line 1101)
- Test: `internal/db/db_test.go`

**Interfaces:**
- Produces: `func (d *DBRepository) warnGlobalVaultManageGrants(db *sql.DB)` — unexported, called only from `migrateSchema`.

- [ ] **Step 1: Write the failing test**

```go
func TestWarnGlobalVaultManageGrants_LogsEachHolder(t *testing.T) {
	database, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer database.Close()

	_, err = database.Exec(`
		CREATE TABLE access_policies (
			id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, principal_type TEXT NOT NULL,
			resource_type TEXT NOT NULL, operation TEXT NOT NULL, effect TEXT NOT NULL,
			vault_id TEXT NULL, assignment_id TEXT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`)
	require.NoError(t, err)

	holder := uuid.New().String()
	// A global allow: must be reported.
	_, err = database.Exec(
		`INSERT INTO access_policies (id, principal_id, principal_type, resource_type, operation, effect, vault_id)
		 VALUES (?, ?, 'user', 'vaults', 'manage', 'allow', NULL)`, uuid.New().String(), holder)
	require.NoError(t, err)
	// A vault-scoped allow: must NOT be reported, it is unaffected by release 2.
	_, err = database.Exec(
		`INSERT INTO access_policies (id, principal_id, principal_type, resource_type, operation, effect, vault_id)
		 VALUES (?, ?, 'user', 'vaults', 'manage', 'allow', ?)`,
		uuid.New().String(), uuid.New().String(), uuid.New().String())
	require.NoError(t, err)

	hook, repo := newLogCapturingDBRepository(t, database) // helper in Step 3
	repo.warnGlobalVaultManageGrants(database)

	var messages []string
	for _, e := range hook.AllEntries() {
		messages = append(messages, e.Message+fmt.Sprint(e.Data))
	}
	joined := strings.Join(messages, "\n")
	require.Contains(t, joined, holder, "the global-grant holder must be named in the log")
	require.Equal(t, 1, strings.Count(joined, "global vaults:manage"),
		"only the global grant is reported; vault-scoped grants are unaffected by release 2")
}

func TestWarnGlobalVaultManageGrants_MissingTableDoesNotPanic(t *testing.T) {
	database, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer database.Close()

	_, repo := newLogCapturingDBRepository(t, database)

	require.NotPanics(t, func() { repo.warnGlobalVaultManageGrants(database) },
		"a diagnostic must never fail startup on a partially-built schema")
}
```

Use `logrus/hooks/test` for the capture hook, matching however the existing `internal/db` tests assert on log output; if they do not capture logs at all, add the smallest hook helper needed rather than restructuring the logger.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/ -run TestWarnGlobalVaultManageGrants -v`
Expected: FAIL — method undefined.

- [ ] **Step 3: Write the diagnostic**

```go
// warnGlobalVaultManageGrants logs (never fails) every principal holding a
// global -- vault_id IS NULL -- (vaults, manage, allow) access policy.
//
// Such a policy currently confers far more than the ability to create vaults.
// accessPolicyRepository.FindEffects matches
// "(vault_id = ? OR vault_id IS NULL)", so a NULL-scoped allow satisfies every
// vault-scoped CheckAccess: it grants get/update/delete on every existing
// vault via CanManageVault, and role-assignment management everywhere via
// CanManageRoleAssignments -- which is enough to self-award Key Vault
// Administrator in any vault.
//
// A planned follow-up release narrows that to create-and-list only. This
// diagnostic exists so operators can see, before upgrading, exactly which
// principals will lose those two behaviours. Provisioning grants
// (vault_provisioning_grants) are the bounded replacement.
//
// A query error here is expected and harmless on partially-built schemas (for
// example a migrateSchema-only test fixture with no access_policies table), so
// it is logged at warn level and swallowed.
func (d *DBRepository) warnGlobalVaultManageGrants(db *sql.DB) {
	rows, err := db.Query(`
		SELECT principal_id, principal_type
		FROM access_policies
		WHERE resource_type = 'vaults' AND operation = 'manage'
		  AND effect = 'allow' AND vault_id IS NULL`)
	if err != nil {
		d.log.WithError(err).Warn("Failed to check for global vaults:manage grants")
		return
	}
	defer rows.Close() //nolint:errcheck

	for rows.Next() {
		var principalID, principalType string
		if err := rows.Scan(&principalID, &principalType); err != nil {
			d.log.WithError(err).Warn("Failed to scan global vaults:manage grant")
			return
		}
		d.log.WithFields(logrus.Fields{
			"principal_id":   principalID,
			"principal_type": principalType,
		}).Warn("Principal holds a global vaults:manage grant, which confers management of EVERY vault and role-assignment management everywhere; a future release narrows this to create-and-list only. Consider replacing it with a bounded vault provisioning grant.")
	}
	if err := rows.Err(); err != nil {
		d.log.WithError(err).Warn("Failed to iterate global vaults:manage grants")
	}
}
```

Call it from `migrateSchema` immediately after `d.warnMismatchedRotationPolicyVaults(db)` (line 1101), before the `"Schema migration completed"` log.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/db/ -v`
Expected: PASS

- [ ] **Step 5: Verify against a real instance**

```bash
go run main.go --config /tmp/rv-test.yaml serve 2>&1 | grep -i "global vaults:manage"
```

On a clean instance this prints nothing, which is the correct result — global grants are only ever created by hand through the admin-only `createAccessPolicy` (`api/access_policies.go:115-121`); `ExpandRole` always sets a concrete `VaultID` (`roles.go:182`) and Azure roles expand to nothing (`:163`).

- [ ] **Step 6: Commit**

```bash
git add internal/db/db.go internal/db/db_test.go
git commit -S -m "feat(db): warn on global vaults:manage grants at startup"
```

---

### Task 2: Documentation

**Files:**
- Modify: `.claude/manual-testing-plan.md` (new subsection in §5, Vault Lifecycle)
- Modify: `.claude/roadmap-azure-parity-and-beyond.md` (mark release 1 shipped)
- Modify: `CLAUDE.md` (CLI Authorization section)
- Create: `docs/release-notes/v4.2.0-vault-provisioning.md`

**Interfaces:** none — documentation only.

- [ ] **Step 1: Add the manual test procedure**

Add to `.claude/manual-testing-plan.md` §5, after the webhook subsection, following that section's `- [ ]` checklist style:

```markdown
#### Self-service vault provisioning (bounded creation right)

- [ ] As admin: `rocketvault vault-provisioning grant <principal> --quota 2`
      → grant issued. Re-run with `--quota 5` → quota changes, `list` still
      shows exactly one grant for that principal (`principal_id` is UNIQUE).
- [ ] `--quota 0` and `--quota -1` → both refused. A zero-quota grant and no
      grant at all are the same permission.
- [ ] Issue a grant to an OAuth2 **service account** by UUID (§3.5) → works.
      A service account is not a `users` row, so a username-only path would
      fail here; this is the MSP automation's actual identity.
- [ ] As the grantee (not an admin): create a vault → succeeds, and
      `rocketvault vaults list` now shows it. Before this feature the grantee
      got 403 on both.
- [ ] Create up to the quota, then one more → the last is refused with a quota
      error naming the count and the limit.
- [ ] Soft-delete one of the grantee's vaults, then create again → **still
      refused**. A soft-deleted vault holds its name and is recoverable, so it
      keeps its quota slot. Purge it, then create → now succeeds.
- [ ] Grantee tries `--purge-protection` on create → refused. Allowing it would
      let the grantee pin a quota slot permanently, since `PurgeVault` refuses
      a protected vault.
- [ ] Grantee has full rights over its own vault (read/write secrets, manage
      role assignments) but **403 on a vault it did not create** — check both
      CLI and HTTP.
- [ ] Grantee tries to raise its own quota via
      `PUT /api/v1/vault-provisioning-grants/{own_id}` → `403`. This tier is
      admin-only and deliberately non-delegable.
- [ ] Revoke the grant → grantee can no longer create, but **keeps** its
      existing vaults and its rights over them. Revocation is not a cascade.
- [ ] Purge a provisioned vault, then check the DB: no orphan row remains in
      `role_assignments` for it (the FK cascade is inert on SQLite).
- [ ] Start the server against a DB where some principal holds a global
      `vaults:manage` policy → a warn line names that principal at startup.
```

- [ ] **Step 2: Update the roadmap**

In `.claude/roadmap-azure-parity-and-beyond.md`, under "High priority — multi-tenancy gaps", mark the self-service bullet as shipped for release 1 and record what remains: the narrowing (release 2), name prefixes, and the tenant entity.

- [ ] **Step 3: Update CLAUDE.md**

In the **CLI Authorization** section, add `vault-provisioning` to the list of packages with their own package-local authz helpers, noting it is admin-only and non-delegable — unlike the `vaults` and `vault-access` helpers, it has no access-policy or role-assignment path at all.

- [ ] **Step 4: Write the release note**

Create `docs/release-notes/v4.2.0-vault-provisioning.md` covering: what a provisioning grant is; the admin API and CLI; that quota counts soft-deleted vaults; that grantees cannot set `purge_protection`; that revocation is not a cascade; the `role_assignments` purge fix; and **an explicit forward notice** that a following release will narrow global `vaults:manage` to create-and-list, with the startup diagnostic named as the way to find affected principals before upgrading.

- [ ] **Step 5: Verify the docs build**

Run: `./scripts/docs.sh build`
Expected: succeeds, and the new release note renders.

- [ ] **Step 6: Commit**

```bash
# .claude/ is gitignored; only the tracked files are added here.
git add CLAUDE.md docs/release-notes/v4.2.0-vault-provisioning.md
git commit -S -m "docs: document vault provisioning grants"
```

Mention to the user that the `.claude/` edits are intentionally uncommitted, and ask before `git add -f`.

---

## Release 1 complete

After this plan, verify the whole feature end to end:

```bash
go build ./... && go vet ./... && go test ./... -race
```

Then walk §5's new manual subsection against a scratch instance (`.claude/manual-testing-plan.md` §0 for isolated-config setup).

**Release 2 is a separate spec section and is not planned here.** It implements `CheckVaultScopedAccess` and narrows both `CanManageVault` and `CanManageRoleAssignments` — see the design doc's §2 and §9. Do not start it until this diagnostic has reported from a real deployment.
