# Plan 07 — Verify A–Q — progress ledger

Plan: `docs/superpowers/plans/2026-09-06-journeybook-detail-07-verify-a-q.md`
Branch: `v-4.0.0` (in place)
Started: 2026-09-06

## Deviation from the plan, carried forward from plan 06

The plan's three prompts reference `answers-cli.json` and `answers-authz.json`.
Plan 06 produced a single `answers-code.json` instead (documented deviation —
the worklist was four questions, not enough to justify two agents). All three
dispatches were adjusted to name the file that exists, and each was told
explicitly which of J1/J4/G9 fall in its range so nobody hunts for entries that
are not there.

## Gate 3 honoured

All three verifiers are **fresh agents**. None wrote any of the work it checks,
and none was resumed from an extraction agent — a resumed agent has its own
output in context and defends it.

## Tasks

### Task 1 — Verify A–F — COMPLETE
- [x] Step 1: fresh sonnet verifier → `verdicts-a-f.json`
- [x] Step 2: read findings; hand spot-check two `supported` verdicts

**Result: 36 fields — 34 supported, 2 overstated, 0 contradicted, 0 not-found.**
All 14 `related[].id`s resolve; no dangling references.

Both findings are the exact failure the prompt targeted — a claim that is TRUE
but reaches past ITS OWN citation:
- **C21.why (overstated)** — cited only `§ Correction 9`, which supports that
  `cmd/keys.go` registers no `import` subcommand. The claims about
  `ActionKeysImport` being in the Crypto Officer bundle and no HTTP route
  existing are true but live in `model/azure_roles.go` and Journey C's closing
  paragraph, not the cited section.
- **D6.why (overstated)** — cited only the `RoleKeyVaultCryptoUser` bundle,
  which supports that `update` and `backup` are included. The "master-key-
  encrypted ciphertext, not plaintext PEM" characterisation comes from Journey
  D's "Threat-model precision" note, which is not in the citation.

Two additional citation-tightening flags (verdict stands, range is imprecise —
the supporting line sits just past the cited range's end):
- **B9.why** cites `role_assignment_service.go:114-141`; the "returns existing
  unchanged" branch is at `:143-145`.
- **C12.why** cites `key_service.go:1112-1127`; the new-version write is at
  `:1128-1131`.

**Spot-check (2 supported verdicts, opened by hand):** both correct.
- `E3.why` — `cmd/keys/wrap.go:125` hardcodes `Algorithm: "RSA-OAEP"`, and the
  flag block registers only `--key-id`, `--key-material`, `--version`. A grep
  for an `"algorithm"` flag across wrap.go and unwrap.go returns nothing.
- `E5.why` — `model/azure_roles.go:207-209` gives
  `RoleKeyVaultCryptoServiceEncryptionUser` exactly
  `{ActionKeysRead, ActionKeysWrap, ActionKeysUnwrap}`. No encrypt action.

### Task 2 — Verify G–M including the J pilot — COMPLETE
- [x] Step 1: fresh sonnet verifier → `verdicts-g-m.json`
- [x] Step 2: read findings, **J verdicts first**

**Result: 40 fields — 34 supported, 4 not-found, 2 overstated, 0 contradicted.**
All `related[].id`s resolve; no hedging found.

**THE PILOT HELD: Journey J is 10 of 10 supported.** No escalation to the human
was needed. The plan's contingency — "if J's own claims did not survive, the
four groups that copied its shape need re-examining, and that is a decision to
take to the human before continuing rather than after" — did not trigger.

J came back 100% supported, which is the plan's own rubber-stamp warning sign,
so I hand-checked its two most load-bearing claims rather than accepting the
run. **J5 confirmed from both sides independently:**
- `VAULT_USER_ACCESS_JOURNEYS_v3.md:695-721` (Journey K) states it outright —
  "CLI — admin bypass in `CanPurgeVault`" — with a table showing admin-with-no-
  grant succeeding on CLI and taking 403 over HTTP.
- `internal/services/authorization/vault_authz.go:61-63` opens `CanPurgeVault`
  with `if common.HasAnyRole(accountRoles, RoleAdmin) { return true }`.
Direction correct, not mirror-imaged. This was the claim the plan singled out
for scrutiny, and it survives.

The verifier's confidence in J is also not blind: the same agent flagged 6
problems in the surrounding G–M cases, so it was not passing everything.

**Six findings, four of one kind.** All four `not-found` are *citation
misattribution* — the claim is true, but cited to a section that does not
contain it:
- **G3.why / G8.why** — cited to the Corrected Cast table. The cast row explains
  why Wren's **global account role** is `user`; it says nothing about what the
  vault-scoped `Key Vault Data Access Administrator` role grants, nor about
  access policies. Both facts are demonstrated in Journey G's body
  (`:521-527`, `:540-543`).
- **H6.why** — cited to Journey I. The sentence quoted is real but is Journey
  I's explanation of **Gate-3 role-assignment** revocation (I5); Journey I never
  mentions access policies. Journey H does say "revert instantly, no restart, no
  cache flush" (`:592-596`) but never names PolicyMiddleware/HasDataAction.
- **M3.why** — cited to Journey I, which is exclusively about role-assignment
  revocation → 403 and never discusses user deletion or 401. The fact is in
  Journey M's own text (`:790-796`).

Two overstated:
- **K2.why** — cites Journey K for `RouteVaultData`/`ActionVaultPurge`/
  `PolicyMiddleware`. The verifier grepped the whole document: `RouteVaultData`
  appears nowhere, `ActionVaultPurge` only in Journey J, `PolicyMiddleware` only
  in Journey I. Journey K supports the *outcome*, not the named mechanism.
- **M5.why** — cites Global Setup for `users logout` behaviour. Global Setup
  covers only where the session cache lives; the logout semantics are in Journey
  M (`:804-806`).

**Independent validation of plan 06's answers.** This verifier checked the
`answers-code.json` versions of G9/J1/J4 against source and found all three hold.
It also made an observation worth keeping: the *old* J4.after said "restore it
explicitly" without warning that no CLI command can do it at all — "a QA
engineer following only the old wording could go hunting for a nonexistent
`secrets restore` subcommand." That is the concrete argument for hand-applying
J1/J4 in plan 09 rather than letting the older text stand.

### Task 3 — Verify N–Q — COMPLETE
- [x] Step 1: fresh sonnet verifier → `verdicts-n-q.json`
- [x] Step 2: read findings; hand spot-check two `supported` verdicts

**Result: 34 fields — 31 supported, 1 overstated, 1 contradicted, 0 not-found.**
All 9 `related[].id`s resolve.

- **Q1.why (contradicted)** — the claim says Journey G enumerates the allow-list
  "and the other three are shown being refused". Journey G
  (`VAULT_USER_ACCESS_JOURNEYS_v3.md:505-546`) shows only **two** of the three
  excluded roles refused: Purge Operator (`:530-531`) and Data Access
  Administrator (`:533-534`). **Key Vault Certificate User never appears in
  Journey G at all** — its only mention in the whole document is `:1201`, in an
  unrelated journey, where it is *granted* rather than refused.
- **Q11.why (overstated)** — claims `UpdateCertificate` "overwrites only Name,
  Tags, AutoRenew, RenewalDays, Enabled and the validity window", stated as
  exhaustive. `UpdateCertificateRequest` also carries `PurgeProtection *bool`
  and `certificate_service.go:662-663` calls `SetPurgeProtection` when non-nil
  — just past the cited range. The point Q11 actually tests (the PEM and key
  material are never touched) is supported.

**Spot-check (2 supported verdicts, opened by hand):** both correct.
- `O7.why` — `cmd/secrets/import.go:155-158` has exactly the claimed split: a
  fixed `"failed to decrypt %s: wrong passphrase or corrupted file"` for
  `ErrWrongPassphrase`, and a `%w`-wrapped fall-through otherwise.
- `P7.verify` — Journey P shows `--interval 30`, `Interval: 30 days`, and the
  literal `(next: 2026-09-24)` the claim warns testers not to match on.

## Cross-validation worth recording

**Q1's contradiction independently corroborates plan 06's G9 answer.** G9's open
question was that the document names only two of the three excluded roles. Plan
06's Opus agent answered "the third is Key Vault Certificate User" from
`role_assignment_service.go`'s exclusion comment. This verifier — a different
agent, working from the other direction, checking a different case — found the
same gap in the document and named the same missing role. Two independent paths
to the same fact.

## The plan's named risk did not materialise (for the two finished groups)

The risk was a verifier rubber-stamping, which produces output indistinguishable
from a clean pass. Neither group came back 100% supported (A–F: 2 of 36 flagged;
N–Q: 2 of 34), and all four hand spot-checks confirmed the verdicts, so both
verifiers were reading sources rather than reading for plausibility.

## Note on findings' severity

None of the four findings is a false claim. All four are claims whose text is
accurate but whose citation does not carry the whole of it, plus one (Q1) where
the document genuinely does not show what the claim says it shows. These are
rewrite-down-to-the-citation fixes, applied in **plan 08 Task 3**, not here —
verifiers report, they do not cut.

## Plan complete — A–Q verified

| File | Fields | supported | overstated | not-found | contradicted |
|---|---|---|---|---|---|
| `verdicts-a-f.json` | 36 | 34 | 2 | 0 | 0 |
| `verdicts-g-m.json` | 40 | 34 | 2 | 4 | 0 |
| `verdicts-n-q.json` | 34 | 32 | 1 | 0 | 1 |
| **TOTAL** | **110** | **100** | **5** | **4** | **1** |

**10 of 110 fields (9%) did not survive.** No data file modified; nothing cut.
Plan 08 Task 3 applies every cut, once, in one place.

**What the 10 findings are not:** none is a false statement about how RocketVault
behaves. Nine are claims whose *text* is accurate but whose *citation* does not
carry it — either reaching past the cited range (overstated) or citing a section
that does not contain the fact at all (not-found). The tenth, Q1, is the one
place the document genuinely does not show what the claim says it shows.

That distribution is itself a result worth recording: the extraction agents were
reliable about the system and unreliable about provenance. Gate 1 was the right
gate to build the whole effort around, and Gate 3 caught precisely the class of
error Gate 1 was designed to prevent leaking through.

## Rulings I made

**Spot-checked six `supported` verdicts by hand, not the plan's four.** The plan
asks for two per group in Tasks 1 and 3. I did those (`E3`, `E5`, `O7`, `P7`) and
added two more for Journey J, because J came back 100% supported and 100% is the
plan's own rubber-stamp signal. All six confirmed.

**Did not escalate to the human.** The plan's Task 2 Step 2 contingency is
conditional on J's claims failing. J went 10 for 10, so the condition was not met
and there was nothing to take upstairs. Recording the non-event explicitly,
because a skipped step and a step whose condition did not fire look identical
after the fact.

## Deferred

- **Citation tightening (2, from A–F):** `B9.why` cites
  `role_assignment_service.go:114-141` but the supporting branch is at `:143-145`;
  `C12.why` cites `key_service.go:1112-1127` but the new-version write is at
  `:1128-1131`. Verdicts stand as supported — the ranges are merely short. Fix
  alongside the plan 08 Task 3 cuts, since the file is open anyway.
- **Q1 vs G9 cross-validation** is recorded above and should survive into
  whatever plan 10 writes: two independent agents, working from opposite
  directions on different cases, found the same documentation gap and named the
  same missing role (Key Vault Certificate User).
