# Plan 10 — Document the Contract — progress ledger

Plan: `docs/superpowers/plans/2026-09-06-journeybook-detail-10-document.md`
Branch: `v-4.0.0` (in place)
Completed: 2026-09-06 — the last plan in the chain

## Tasks

- [x] Task 1: fold the gates into `authoring-cases.md`; delete the brief — `55d3846`
- [x] Task 2: correct README, `journeybook/CLAUDE.md`, root `CLAUDE.md` — `84f2fae`
- [x] **Task 3 (added, not in the plan):** apply the approved corrections — `6775105`

## Task 3 was added, and why

Plan 10 as written covers documenting the contract and nothing else. It does not
carry the **seven source-document corrections the user approved during plan 06**,
nor D2's rewrite. The plan-09 ledger flagged that plan 10's scope needed
widening; without it the chain would have ended with
`docs/VAULT_USER_ACCESS_JOURNEYS_v3.md` still asserting behaviour the code does
not have, and one case that cannot pass on any build.

The decision was already the user's, taken explicitly in plan 06. Executing it
is completing agreed work, not expanding scope, so it was done rather than
re-asked.

## D2 was four cases, not one

The most consequential finding of this plan. D2 was presented to the user as a
single unpassable case: it expects `vault-access list --vault prod --output json`
to emit `principal_username`. `cmd/vault-access/list.go:25,28,76,78` writes a
fixed `ASSIGNMENT-ID`/`ROLE`/`PRINCIPAL-ID` table with `fmt.Fprintf`, never reads
`--output`, and prints a raw UUID.

Grepping before editing showed the same non-existent JSON in **four journeybook
cases** (D2, H5, and two assignment-id captures) and **seven places in the
document**. Fixing only D2 would have left three equally unpassable checks and a
document still teaching the wrong invocation. All are now filtered on the
`PRINCIPAL-ID` column with `awk` instead of piped to `jq`.

The user approved "rewrite D2 to match the real CLI". Applying that same fix to
the three identical instances is the only coherent reading of it, but it is
worth recording that the scope was wider than what was presented.

## One cascade caught

Adding `Key Vault Certificate User` to Journey G's refusal demonstrations made
plan 08's own correction to `Q1.why` stale — that rewrite said Journey G "shows
two of the three excluded roles", which was true when written and false once the
document was fixed. Updated to "all three" in the same commit.

This is the kind of second-order breakage a correction pass creates and does not
announce.

## No code defects to file

The plan's closing note says a code defect found during the backfill belongs in
`.claude/known-bugs.md` rather than a commit message. **There are none to file**,
and that is worth stating rather than leaving silent:

- All seven corrections were doc rot. In every case the code was right and the
  document was stale or wrong — twice because someone fixed the code
  (`1a58a88`, `9353568`) and did not update the document.
- The one genuine code gap — `vault-access list` having no `--output` support —
  was put to the user in plan 06 with "rewrite AND file the gap" as an option.
  They chose the rewrite alone. **Deliberately not filed.**
- `T17` surfaced that remote and local denial messages differ in wording
  (`internal/cliclient/apierror.go` vs `cmd/vault-access/authz.go:42`). A real
  inconsistency, not a defect, and out of scope here.

## Final state

`typecheck`, `lint`, `check:links` (245 cases, **161 carrying detail, 0
problems**), `check-contrast` (0 failing in both themes) and `build` all pass.
Artifact is 679 kB raw, 250 kB gzipped.

Working tree carries only the concurrent sessions' files. Every commit in this
chain is GPG-signed and path-scoped; nothing of theirs was ever staged.

## Deferred

- **The rendered-page walk is still not done** — carried from plan 09. Section
  order with 161 populated cases has not been looked at by a human.
  `journeybook/dist/journeybook.html` is built and current.
- `cuts.md`, `questions.md` and the five verdict files live only in the session
  scratchpad. They are the audit trail for what was cut and why. Nothing
  references them from the repository, so they will be lost when the scratchpad
  goes. If that record matters, it needs a home.
