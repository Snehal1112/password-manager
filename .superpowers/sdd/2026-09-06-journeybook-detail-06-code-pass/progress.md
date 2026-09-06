# Plan 06 — The Code Pass — progress ledger

Plan: `docs/superpowers/plans/2026-09-06-journeybook-detail-06-code-pass.md`
Branch: `v-4.0.0` (in place, user's standing decision)
Started: 2026-09-06

## Concern raised before starting (executing-plans Step 1.4)

**The worklist is not the shape plan 06 assumed.** The plan provisions two Opus
agents split by tree area, sized for a large code-reading effort. Collating all
64 `needs-code` entries shows:

| Kind | Count | Needs code? |
|---|---|---|
| Notes-deduplication instructions | 54 | No — plan 09 merge instructions |
| Genuine code questions | 4 | Yes — J1, J4 (cmd/), A5, G9 (authz/model) |
| DISAGREEMENTs | 6 | No — for a human |

**Deviation taken:** one Opus agent for all four questions instead of two split
by bucket. Two agents each answering two questions is disproportionate for no
gain in isolation. The plan's substance is unchanged — code-sourced answers, a
`file.go:line` on each, the three ANSWERED/UNRESOLVED/DISAGREEMENT outcomes, and
the three-citation spot check.

**Second deviation:** `questions.md` has a fourth section the plan did not
specify, holding the 54 notes-deduplication entries. The plan says to sort each
question into exactly one of two code buckets (plus disagreements), and 54 of
them fit neither — they need no code at all. Filing them into a code bucket
would have sent an Opus agent to read Go for questions Go cannot answer.

## Merge hazard found in pre-flight — carries to plan 09

`j.json`'s two questions target fields that are **already applied**: J1 has a
shipped `verify`, J4 a shipped `after` (Journey J landed in plan 03). Any answer
amends an existing field, so the merge script will refuse them — correctly. Both
must be **hand-applied in plan 09, not machine-merged.** Recorded in
`questions.md` § 1 as a warning, and the agent was told to write each answer as
a complete replacement field rather than a fragment.

This is the second apply-set hazard for plan 09, alongside "`j.json` itself is
spent and must be excluded" from plan 05's ledger.

## Tasks — ALL COMPLETE

- [x] Task 1: Collate open questions → `questions.md` (64 entries, 4 sections)
- [x] Task 2: Resolve the code questions → `answers-code.json`; spot-check 3
- [x] Task 3 Step 1: folded into Task 2's single agent (documented deviation)
- [x] Task 3 Step 2: **STOP** — all six disagreements put to the user
- [x] Task 3 Step 3: Decisions recorded in `questions.md`

## Task 2 result

Three ANSWERED, one UNRESOLVED, no new disagreements.

- **J1** `verify` — no CLI flag lists soft-deleted secrets. Agent went further
  and found the HTTP route that *does* return `deleted_at`
  (`api/soft_delete.go:405`) is useless here specifically: it resolves the vault
  by name through a `WHERE name = ? AND deleted_at IS NULL` query
  (`internal/repositories/vault_repository.go:134`), so it 404s for exactly the
  window J1 runs in. Shipped no `verify.command` — a sqlite3 query would have
  been invented rather than confirmed (Gate 2).
- **J4** `after` — no CLI command restores one soft-deleted secret; REST only.
- **G9** `why` — the third excluded role is **Key Vault Certificate User**.
- **A5** — UNRESOLVED. See below.

**Spot-check (plan-mandated, 3 citations):** all pass. I deliberately picked the
highest-consequence ones rather than at random.
- `role_assignment_service.go:27-45` — the source comment states the exclusions
  outright ("deliberately excludes RoleKeyVaultDataAccessAdministrator itself,
  RoleKeyVaultPurgeOperator, and RoleKeyVaultCertificateUser"), so G9 is right by
  statement, not merely by subtraction. Allow-list has exactly 8 entries.
- `cmd/secrets/list.go:217` — registers only `--tags`. Confirmed.
- **J4's negative claim, checked separately** because a wrong negative sends a
  tester hunting for a command that exists: `cmd/secrets/` registers create,
  delete, export, generate-password, get, import, list, update and nothing else;
  the only `restore` is `cmd/backup.go:176` (whole-database); `RecoverSecret` has
  zero production callers under `cmd/`, only a test mock. Confirmed.

**The plan's named known risk did not materialise.** The risk was that an Opus
agent asked to settle a question from code will settle it, with UNRESOLVED
feeling like failure. A5 asked whether a *documented rationale* exists for
vaults using partial updates while rotation policies use full-replace. The agent
searched docs/, .claude/, specs, plans, release notes and non-test Go comments,
found the mechanism on both sides, found no stated rationale, and returned
UNRESOLVED without constructing a plausible one. It noted the mechanism is
citable if a human later wants a mechanism-only `why`, but did not write it.

## Merge state for plan 09

- `answers-code.json` G9 → merges cleanly (dry run: 1 case).
- `answers-code.json` J1, J4 → **hand-apply.** Verified they trip the guard, as
  predicted in pre-flight. Both are written as complete replacement fields.

## Decisions taken by the user (2026-09-06)

1. **Correct both the journeybook and `docs/VAULT_USER_ACCESS_JOURNEYS_v3.md`.**
   Deliberately widens scope past "enrich the journeybook", because fixing only
   the journeybook leaves the source doc wrong and the next regeneration from it
   reintroduces all six.
2. **D2: rewrite to match the real CLI** — assert the actual
   `ASSIGNMENT-ID/ROLE/PRINCIPAL-ID` table. **Explicitly not chosen:** filing the
   missing `--output` support as a bug. Do not file it.

Full text with per-case corrections is in `questions.md` § Decisions.

**Consequence for the remaining plans:** the source-doc corrections are work
this chain never planned for. Plan 10's scope needs widening to cover them, and
plan 09 carries the journeybook-side fixes.

## All six disagreements verified by me at source

Not relayed from agent reports — I opened each cited location myself, so the
decision put to the user rests on read source. Plan 04 raised five and plan 05
raised one; all six survive independent checking.

1. **A7** — `model/azure_roles.go` has `Microsoft.KeyVault/vaults/keys/read`
   with no trailing `/action`; formatted by
   `internal/services/authorization/data_action_authz.go:35`. The case (and the
   doc at line 135) expect `/action`. Confirmed.
2. **D2** — `cmd/vault-access/list.go` never reads `--output` and prints a fixed
   `ASSIGNMENT-ID/ROLE/PRINCIPAL-ID` table with a raw UUID. The case expects
   `--output json` with `principal_username`. That field exists only on the HTTP
   API's `model.RoleAssignmentResponse`. **The case can never pass.** Confirmed.
3. **C3 (a)** — `cmd/keys/create.go:192` reads
   `ECDSA curve (P-256, P-384, P-521, P-256K)`. The doc's "`--curve`'s help
   omits P-256K" premise is stale; fixed by `1a58a88` (2026-08-19), which is a
   real commit. The underlying `type == "ECDSA"` trap the case demonstrates is
   still real. Confirmed.
4. **C3 (b)** — `cmd/keys/get.go:109` declares headers
   `{"ID","Name","Type",...}`, and the JSON formatter uses headers verbatim as
   keys, so the real key is `Type`. The case pipes `jq .type`, which returns
   `null`. Confirmed.
5. **C4** — `cmd/keys/create.go:191` reads
   `RSA key size in bits (2048, 3072 or 4096)`. The case's "despite the help
   text" framing is stale; fixed by `9353568` (2026-08-22), a real commit. 3072
   is still accepted, so only the framing is wrong. Confirmed.
6. **Q5** — `cmd/certificates/create.go` gates on
   `HasAnyRole(admin, certificate_manager)` at line 74, **before** the
   required-fields check at line 88; only `RequireDataAction` at 115 runs after
   flag validation. The doc says flag validation runs "before any authorization
   or key lookup". Confirmed.

Pattern worth putting to the user: in **five of six**, the code is right and the
document is stale or wrong. Only D2 describes a case that cannot pass at all.

## Rulings I made

(see Concern section above — two deviations, both recorded)

## Deferred

(none yet)
