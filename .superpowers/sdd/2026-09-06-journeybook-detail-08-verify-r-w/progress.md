# Plan 08 — Verify R–W and Apply the Cuts — progress ledger

Plan: `docs/superpowers/plans/2026-09-06-journeybook-detail-08-verify-r-w.md`
Branch: `v-4.0.0` (in place)
Started: 2026-09-06

## Deviations, both carried from earlier plans

1. **Answer-file path.** Both prompts reference `answers-cli.json` and
   `answers-authz.json`; plan 06 produced a single `answers-code.json`. Adjusted,
   and each verifier told it holds only J1/J4/G9 so nobody hunts for entries in
   its range that do not exist.

2. **Added a guard the plan does not have, to the V–W prompt.** The plan tells
   the verifier the asymmetry is "deny matches every vault, allow matches none"
   and to treat a reversal as `contradicted`. Left there, that instruction would
   have produced a **false positive**: W3 and W4 correctly state that at
   `vaultID == uuid.Nil` the collection-level `CheckAccess` path *is* satisfied
   by a NULL-scoped allow, which is why create and list survive the narrowing.
   A verifier holding only the short form would read those as violations and
   Task 3 would then cut two accurate claims. The prompt now draws the
   distinction explicitly: the asymmetry governs decisions about a **concrete**
   vault. Confirmed against `v4.6.0-narrow-global-vault-manage.md:12,48,197`.

## Pre-flight checks done before Task 3

**`needs-code` deletion is safe — but only because of a step I took in plan 06.**
Task 3 Step 2 says to delete the `needs-code` arrays because "they have all been
through plan 06 by now". That is true of the 4 code questions and 6
disagreements. It is **not** true of the other 54: those are notes-deduplication
instructions that plan 09's merge has not executed yet, and deleting them from
the JSON with no other copy would silently drop the whole worklist.

They survive because `questions.md` § 4 records all 54 verbatim (verified: the
section header reads "Notes deduplication — plan 09 merge instructions (54)").
So the deletion is safe as written. Recording the dependency because it is not
obvious from either plan.

**Journey S scripting trap, hand-read (Task 1 Step 2 requires it):** the document
at `VAULT_USER_ACCESS_JOURNEYS_v3.md:~1420` reads "typing anything other than the
exact string `yes` — including a blank line — prints `Aborted.` and **exits 0**".
That matches S8's `why` exactly, and matches `cmd/master_key.go:243-246`
(`confirmation != "yes"` → print `Aborted.` → `return nil`), which I verified
independently back in plan 05. Document, code and claim all agree. This is the
plan's named "one claim where being wrong causes a tester to certify a
maintenance job that silently did nothing", and it is right.

## Tasks

### Task 1 — Verify R–U — COMPLETE
- [x] Step 1: fresh sonnet verifier → `verdicts-r-u.json`
- [x] Step 2: read the four high-weight findings

**Result: 41 fields — 37 supported, 1 overstated, 2 contradicted, 1 not-found.**
All `related[].id`s resolve, including the three cross-file ones (U6→K3,
U8→C20, U2→U1).

**All four high-weight claims: supported, and code-verified by the agent.**
- R7 (unrecoverable without the pre-rotation key) — unhedged, matches the doc's
  own unqualified "There is no recovery path if it's gone".
- S8 (exits 0 on abort) — `cmd/master_key.go:242-246`, nil error from a Cobra
  `RunE` is exit 0. Correct.
- S3 (nothing stops a live-server rotation) — no PID/lock check in
  `runMasterKeyRotate`; the only guard is the per-row ciphertext match.
- T19 (`ROCKETVAULT_VAULT`: vault-access reads it, secrets does not) — correct
  direction, not reversed.

### MY ERROR, caught by the gate — T7.why contradicted

**The false claim originated in my own plan-05 dispatch prompt.** I wrote:
"no blast radius elsewhere because every other group is still behind a loud
'remote mode is not yet supported' guard." The extraction agent followed the
instruction faithfully and wrote it into T7.

It is false, on two counts, both of which I verified myself:
- `cmd/root.go:239-246` — `remoteCapableCommands` contains
  `"vault-access": {grant, list, revoke}`. The document says so outright too:
  "`vault-access` no longer belongs on this list ... has since joined them"
  and, later, "Since `grant`, `list`, and `revoke` joined
  `remoteCapableCommands`, Priya can run ...".
- The claim also called the reused session "silent". The cited section
  explicitly rejects that word: "The danger is real but is 'easy to miss,' not
  'silent.'" — the stale-context lines are real logrus INFO output on stderr
  naming the target server.

This is exactly the failure the verifier-≠-author rule exists to catch. I could
not have found it by re-reading my own prompt, because I would have re-read it
as correct. Recorded prominently so the correction is not lost in Task 3's bulk
edit — and note the same false premise may have shaped neighbouring T cases even
where the verifier passed them; **re-read T4 and T13 during Task 3**, since they
sit closest to the guard claim.

**Other two findings:**
- **T17.why (contradicted)** — the cited section says the remote denial
  "surfaces the same way for all three" vault-access subcommands, i.e.
  consistency among remote paths. The claim turned that into remote and local
  being identical. They differ: remote text comes from
  `internal/cliclient/apierror.go` ("no role assignment in this vault grants the
  required action"), local from `cmd/vault-access/authz.go:42` ("permission
  denied: admin, vaults/manage, or Key Vault Data Access Administrator required
  for this vault"), and `authz_test.go` asserts the distinction.
- **T6.after (overstated)** — first two sentences match the citation verbatim;
  the trailing "`users logout` or `context unset` to actually reset it" does
  not. `common.UnsetCurrentContext()` (`common/context.go:156-166`) clears only
  the context store's `Current` field and never touches
  `~/.rocketvault/sessions/current`. Only `users logout` clears that, via
  `DeleteSessionForServer` (`common/session.go:269-301`), and only when the
  deleted session is the current one.
- **T7.after (not-found)** — cited to Journey O, which is about migrating a
  secret set and never discusses a stale-session prod deletion. A
  whole-document grep for the claim's distinctive phrases returns nothing.

### Task 2 — Verify V–W — COMPLETE
- [x] Step 1: fresh sonnet verifier → `verdicts-v-w.json`
- [x] Step 2: hand-check the NULL-scope asymmetry against the release note

**Result: 35 fields — 32 supported, 2 not-found, 1 overstated, 0 contradicted.**

**The asymmetry survived, and the guard I added earned itself.** The verifier
found no reversal in any W claim, *and* explicitly distinguished the
collection-level exception rather than flagging it. Without the added
instruction it would very likely have marked W3/W4 as contradicted, and Task 3
would then have cut two accurate claims.

**Hand-checked myself, as the plan requires** — two agents having agreed is not
evidence when both could mirror the fact the same way. Read
`internal/services/authorization/access_policy_service.go:89-111` directly:
the deny branch returns `AccessDenied` without inspecting scope at all, while
the allow branch requires `p.VaultID != nil && *p.VaultID == vaultID`. The
function's own closing comment reads "Either no rows, or only NULL-scoped
allows -- which confer nothing here." **Deny matches every vault, allow matches
none.** Confirmed now from the release note, two independent verifiers, and my
own reading of the function.

Findings: V5.why and V14.why `not-found`, V11.why `overstated` — all three are
true claims cited to a source that does not establish them.

### Task 3 — Apply every verdict — COMPLETE
- [x] Step 1: summarise all five verdict files
- [x] Step 2: apply each verdict; write `cuts.md`
- [x] Step 3: report contradictions
- [x] Step 4: confirm every file still parses

**Whole-run total: 185 fields — 168 supported, 7 overstated, 7 not-found, 3
contradicted. 17 changed (9.2%).**

| Group | Fields | supported | overstated | not-found | contradicted |
|---|---|---|---|---|---|
| A–F | 36 | 34 | 2 | 0 | 0 |
| G–M | 40 | 34 | 2 | 4 | 0 |
| N–Q | 34 | 32 | 1 | 0 | 1 |
| R–U | 40 | 36 | 1 | 1 | 2 |
| V–W | 35 | 32 | 1 | 2 | 0 |
| **TOTAL** | **185** | **168** | **7** | **7** | **3** |

**Step 4 verification:** all five extraction files dry-run clean (37/28/31/39/29
= 164 cases) with **zero** `unresolved` lines. `j.json` and `answers-code.json`
correctly refuse as already-applied — hazards 1 and 2, already on record.
`journeybook/` untouched.

## Rulings I made

**Extended citations rather than cutting, where the claim was true.** The plan
offers two outcomes for a non-supported field: rewrite down to the verifier's
`supported_claim`, or delete. For 9 of the 17 a third option was better — the
claim was accurate and the verifier had named the source that actually
establishes it, so the fix was to cite that source. This satisfies Gate 1
(provenance or nothing) without throwing away correct information a tester
benefits from.

Every added citation was opened and confirmed by hand before being written:
`grant.go:103` (no `MarkFlagRequired` — help says required, cobra does not
enforce), `vault_repository.go:158-165` (`SELECT COUNT(*) ... WHERE created_by =
?`, no `deleted_at` filter), `azure_roles.go:189-192` (`ActionKeysImport` inside
the `RoleKeyVaultCryptoOfficer` bundle), `vault_authz.go:61-73`. Moving a claim
from one unsupporting citation to another would have solved nothing.

Split: **9 re-cited, 7 rewritten down, 1 deleted outright** (T7.after, whose
distinctive phrases appear nowhere in the document).

**Reported the contradictions as "nothing to decide", explicitly.** All three
were authoring errors rather than doc rot or code defects, so no decision was
put to the user. Recorded in `questions.md` rather than skipped, because a
skipped step and a step with nothing to report are indistinguishable afterwards.

## Deferred

**A seventh source-doc correction, inside already-approved scope.** Q1's
contradiction surfaced a real gap: Journey G demonstrates only two of its three
role exclusions, and `Key Vault Certificate User` never appears there at all.
The user has already approved correcting
`docs/VAULT_USER_ACCESS_JOURNEYS_v3.md`, so this joins that list as a seventh
item without needing a new decision. Plan 10 executes it.

Note this is the **second independent route to the same finding** — plan 06's
G9 answer reached it from `role_assignment_service.go`'s exclusion comment, this
verifier from the document itself.
