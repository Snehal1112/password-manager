# Plan 05 — Extract N–W — progress ledger

Plan: `docs/superpowers/plans/2026-09-06-journeybook-detail-05-extract-n-w.md`
Branch: `v-4.0.0` (in place, no worktree — user's standing decision)
Started: 2026-09-06

## Pre-flight

Plan reviewed against reality before dispatch. All checks passed:

- Doc line ranges are exact journey boundaries: N–Q = 811–1230 (R starts 1231),
  R–U = 1231–1820 (V starts 1821), V–W = 1821–2176 (doc ends 2176, and that
  range does include the CLI Quick Reference at 2111 and the retained v2
  corrections at 2166, as Task 3 assumes).
- Case counts match the data files exactly: N5 O11 P15 Q16 = 47;
  R11 S12 T20 U9 = 52; V20 W12 = 32. Total 131, completing 245 with plan 04's
  84 (J7 + A–F 41 + G–M 43 ... see plan 04 ledger).
- `journeybook/.claude/enrichment-brief.md` exists (commit b985038).
- Plan 04 complete; `a-f.json` and `g-m.json` present in scratchpad.
- `git status --short journeybook/src/data/` clean.

No concerns raised. Proceeding to dispatch.

## Carried in from plan 04 — NOT resolved here

Five Gate 4 DISAGREEMENTs from `a-f.json` await a user ruling. They are confined
to A–F and resolve at merge time (plan 09), so they do not block this plan.
Plan 06 consumes them.

## Tasks

### Task 1 — Extract N–Q — COMPLETE
- [x] Step 1: Dispatch sonnet extraction agent → `n-q.json`
- [x] Step 2: Dry run + boundary grep + three eyeball checks
- [x] Fix round 1: O9 hedge + unsourced failure claim. Verified — both the
      `should` and the invented `--format json` failure mode are gone, replaced
      with the doc-supported "read back with `--format csv`, never
      `--format json`, however the file identifies itself on disk". `source`
      unchanged, 32 entries intact, hedge grep clean, dry run still 31.

**Agent result:** 32 of 47 enriched, 15 deliberately bare, 6 `needs-code`
(five notes-trim, one DISAGREEMENT). Boundary grep silent, sourceless NONE,
`src/data/` clean.

**Count discrepancy checked, not assumed:** dry run says 31 updates against 32
entries. Correct — Q5 carries only the DISAGREEMENT and no rendering field, so
it contributes nothing to apply. That is Gate 4 working as designed.

**NEW — sixth Gate 4 DISAGREEMENT (Q5), verified by me against source:**

> DISAGREEMENT — the doc states flag validation runs 'before any authorization
> or key lookup', but `cmd/certificates/create.go` checks
> `HasAnyRole(admin, certificate_manager)` at lines 74-77, before the
> `name`/`key-id`/`validity-days` required-fields check at lines 88-91. Only
> the vault-scoped `vaultcli.RequireDataAction` call (line 115) runs after flag
> validation. A caller missing certificate_manager who also omits a required
> flag gets the forbidden error, not the missing-field error — the doc's
> example happens not to exercise this because Noor already holds
> certificate_manager.

I read `cmd/certificates/create.go` directly and confirm the ordering exactly:
role gate at 74, required-fields at 88, `RequireDataAction` at 115. The doc's
claim is wrong for the global-role gate. **This joins plan 04's five as a sixth
item needing the user's ruling.** Unlike those five it is confined to Journey Q,
so it still does not block anything before plan 06.

**Defect found — Gate 5 + Gate 1:** O9's `verify.look` ended "the same file with
`--format json` should fail instead." `should` is banned outright, and worse,
the doc establishes only that a sealed CSV export is read back with
`--format csv` "never `--format json`" — it never states that the wrong form
errors. The clause asserted an unsourced failure mode, which would send a
tester to file a defect against unspecified behaviour. Sent back to restate
flatly inside what the doc supports, with permission to assert a failure only
if a citation is produced.

**Sweep triggered by that finding:** re-ran the hedge grep across all five files
with a widened pattern (adding `seems`/`may be`/`might`/`possibly`/`generally`/
`typically`/`usually` beyond the plan's list). `j`, `a-f`, `g-m`, `r-u`, `v-w`
all clean. O9 was the only hedge in 145 entries.

### Task 2 — Extract R–U — COMPLETE
- [x] Step 1: Dispatch sonnet extraction agent → `r-u.json`
- [x] Step 2: Dry run + boundary grep + Journey S "exits 0 on abort" scrutiny
- [x] Fix round 1: S3 `related` → S4 applied; verified independently (S3 now
      carries `[{"id":"S4","rel":"contrasts"}]`, S3/S4 `why` byte-identical,
      dry run still 39 cases)

**Agent result:** 39 of 52 cases enriched, 13 deliberately bare, 22 `needs-code`
entries — all of them notes-deduplication requests, no open factual questions,
no DISAGREEMENTs.

**Step 2 checks run:**
- Dry run: `39 case(s) across 1 file(s)`, resolves cleanly.
- Boundary grep for `"[N-Q][0-9]+":` — silent. Agent stayed in its half of the
  shared file.
- Hedge grep (widened beyond the plan's list to include `seems`/`may be`/`might`)
  — silent.
- `git status --short journeybook/src/data/` — clean.

**Citations I re-opened myself rather than trusting (Gate 3 applied to my own
review, not just deferred to plans 07/08):**
- S8's "exits 0" — `cmd/master_key.go:243-246`: `confirmation != "yes"` →
  `Aborted.` → `return nil`. Exact.
- T19's "plan 07 migrates the secrets remote adapters" — verbatim doc text at
  `VAULT_USER_ACCESS_JOURNEYS_v3.md:1723`. Sourced, not inferred.
- U9's webhook spec — `docs/superpowers/specs/2026-08-20-webhook-delivery-primitive-design.md:4`
  is `**Status:** Proposed`. Exact.

**Journey S vagueness check (plan-mandated):** S8 passes. Its `why` states the
exact-string condition, names the blank line, states the exit code flatly, and
keeps `--yes` as the fix. Not vague; not sent back.

**One finding, sent back as a fix:** S3's `why` says nothing enforces stopping
the server; S4 carries the other half of that same doc sentence (the narrower
ciphertext guard — a live-server write matches zero rows and the batch aborts).
The split is faithful to the doc and both texts are accurate, so no rewrite was
warranted. But S3 had no `related` edge to S4, so a tester reading S3 alone sees
"nothing stops you" and never reaches the mitigation — which reads as unguarded
corruption when the real behaviour is fail-closed. Asked the agent to add
`{"id": "S4", "rel": "contrasts"}` to S3 and change nothing else.

I deliberately did not author that link myself, to stay reviewer rather than
becoming an author of content I would later verify.

**Deferred to plan 09, not a defect:** T19's `why` says "plan 07" with no
qualifier. It is verbatim from the doc, but inside this effort "plan 07" also
names a journeybook plan file, and a QA reader has no way to tell which is
meant. Worth disambiguating at merge time.

### Task 3 — Extract V–W — COMPLETE
- [x] Step 1: Dispatch sonnet extraction agent → `v-w.json`
- [x] Step 2: Dry run + three checks + NULL-scope allow/deny direction checked
      against `docs/release-notes/v4.6.0-narrow-global-vault-manage.md`
- [x] Fix round 1: three sourceless `verify` fields — agent took Route 1
      (cite, don't delete) for all three. **I re-opened all three citations
      rather than accepting the claim that they were grounded:**
      - V7 + V8 → `cmd/vault-provisioning/list.go:18-31`. Exact: those lines
        are precisely `runList`, and it supports both claims independently —
        `ListGrants(ctx)` takes no vault parameter (so `--vault` cannot change
        the output) and output goes through a fixed `fmt.Fprintf` table that
        never reaches a formatter (so `--output json` yields no JSON).
      - W4 → `VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey W, step 2`, which
        reads "`vaults list` also treats her as an 'all' lister, so she
        **sees** vaults she cannot touch ... listing is not managing." Exactly
        W4's claim.
      Re-check: `sourceless: NONE`, 29 entries, dry run clean.

**Agent result:** 29 of 32 enriched (V4, V9, V10 deliberately bare), 13
`needs-code` (all notes-dedup), no DISAGREEMENTs. Cross-file `related` targets
G1 and J5 resolve.

**NULL-scope direction check — PASSES.** This was the plan's flagged
highest-risk item, and I checked it against the ground truth captured *before*
dispatch so I was verifying rather than being persuaded:
- W11: "A `NULL`-scoped deny is inspected first and always wins; a `NULL`-scoped
  allow is inspected last and never counts." Correct.
- W8: `CheckVaultScopedAccess` "keeps every `NULL`-scoped **deny** row but
  discards `NULL`-scoped **allow** rows". Correct.
- W3/W4 carry the harder nuance correctly: at `vaultID == uuid.Nil` the
  collection-level `CheckAccess` path *is* satisfied by a NULL-scoped allow,
  which is why create and list survive the narrowing. Matches release note
  lines 12/48/197.
Nothing mirror-imaged. The plan's stated known risk did not materialise.

**Defect found — Gate 1:** V7, V8 and W4 each carry a `verify.look` with no
`source`. Gate 1 names `verify` explicitly, and `scripts/check-links.mjs` fails
the build on it, so as written these three would block plan 09's apply. Sent
back with two acceptable routes: cite the source actually checked, or delete the
`verify` block outright (the brief's "omission is a correct outcome"), chosen
per case — explicitly warning against inventing a citation to satisfy the
checker.

**Sweep triggered by that finding:** ran the sourceless check across all five
enrichment files, since a check that catches a defect in one file should be run
on all. `a-f` (41), `g-m` (28), `j` (7), `r-u` (39) are all clean. The problem
is isolated to those three fields in `v-w.json` — an agent oversight, not a gap
in the brief.

## Ground truth captured before verification (so the check is independent)

Task 3 Step 2's NULL-scope direction, read from the release note rather than
from the agent's output or the journeys doc:

- `docs/release-notes/v4.6.0-narrow-global-vault-manage.md:47-48` — `CheckVaultScopedAccess`
  differs from `CheckAccess` in one respect: a `NULL`-scoped **deny** still
  matches, but a `NULL`-scoped **allow** does not.
- `:61-63` — a global explicit **deny** on `(vaults, manage)` still blocks every
  vault, including ones the denied principal created; the asymmetry between deny
  and allow is deliberate, not an oversight.
- `:67-68` — `CheckAccess`/`FindEffects` deliberately keep the `NULL` match so
  global denies keep working on the data plane; narrowing them would have
  silently disabled every global deny.
- `:145` — the upgrade dimension: holders of a `NULL`-scoped
  `(vaults, manage, allow)` policy lose management on upgrade.

So the sentence that must appear in the V–W output is: **deny matches all,
allow matches none.** Reversed is a fail.

## Plan complete — phase 1 done

Combined dry run of the five unapplied files: **164 cases across 4 files**,
clean. `git status --short journeybook/src/data/` empty. Nothing applied.

Per-group tally:

| Group   | Enriched | Bare | needs-code | DISAGREEMENT |
|---------|----------|------|------------|--------------|
| J pilot | 7        | 0    | 2          | 0            |
| A–F     | 41       | —    | 12         | 5            |
| G–M     | 28       | 15   | 9          | 0            |
| N–Q     | 32       | 15   | 6          | 1 (Q5)       |
| R–U     | 39       | 13   | 22         | 0            |
| V–W     | 29       | 3    | 13         | 0            |

171 of 245 cases carry enrichment (164 pending + J's 7 already applied).

**Apply-set note for plan 09 — important.** `j.json` must be EXCLUDED from the
apply. Its content is already in `journeys-g-m.ts` from plan 03, and including
it trips the double-application guard: `J7 already has a "why" property.
Refusing to apply twice.` The guard works; the file is simply spent. Verified
`g-m.json` does not overlap it — its letters are G, H, I, K, L, M with no J, so
the plan-04 agent correctly stayed off the pilot.

The plan-09 apply set is exactly: `a-f`, `g-m`, `n-q`, `r-u`, `v-w`.

## Rulings I made

**Sent one finding back per group rather than batching them to plan 07/08.**
The plan assigns adversarial verification to plans 07/08, but each defect here
was cheap to catch at task-review time and cheaper to fix while the authoring
agent still held context. None of the three pre-empts the independent
verification those plans do.

**Did not author fixes myself.** All three fixes went back to their authoring
agent rather than being hand-applied, to keep me reviewer rather than author of
text I would later be verifying.

**Ran two checks the plan did not specify, across all files.** Both were
triggered by a defect found in one file, on the principle that a check which
catches something in one place should be run everywhere. The sourceless-field
sweep found the V–W issue and cleared 115 other entries; the widened hedge
sweep found O9 and cleared 145.

## Deferred

- **T19's "plan 07"** — verbatim doc text (`VAULT_USER_ACCESS_JOURNEYS_v3.md:1723`),
  so not a defect, but inside this effort "plan 07" also names a plan file and a
  QA reader cannot tell which is meant. Disambiguate at plan 09 merge time.
- **Six DISAGREEMENTs now await a user ruling**, not five: plan 04's A7, D2,
  C3 (×2) and C4, plus Q5 from this plan. Q5 is the second case where the
  document rather than the journeybook is what is wrong, which bears on the
  open scope question of whether correcting
  `docs/VAULT_USER_ACCESS_JOURNEYS_v3.md` is in bounds.
