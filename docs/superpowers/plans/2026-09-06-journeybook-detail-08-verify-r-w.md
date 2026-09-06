# Journeybook Detail — Verify R–W and Apply the Cuts — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify the remaining two groups, then apply every verdict — cutting or rewriting each non-supported field, and reporting the contradictions to a human.

**Architecture:** Two more fresh verifiers, then one consolidation pass that edits the enrichment JSON in place. Cutting happens once, in one task, so there is a single point where a claim can leave the set and a single diff that shows what left.

**Tech Stack:** Agent tool with Sonnet for the two verifications; the consolidation is done directly, not delegated — it is a decision about what ships, and it is short.

**Spec:** `docs/superpowers/specs/2026-09-06-journeybook-case-detail-design.md`

**Prerequisite:** Plan 07 complete; three verdict files present.

**Followed by:** `2026-09-06-journeybook-detail-09-apply.md`.

## Global Constraints

- **A verifier must never have written the work it checks.** Fresh agents only.
- Only `supported` ships. `overstated` is rewritten down to what its citation supports, or cut. `contradicted` and `not-found` are cut and reported.
- Verifiers report; they do not edit. Task 3 is the only place a field is removed.
- Scratchpad root: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/`

---

### Task 1: Verify journeys R–U

**Files:**
- Create: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/verdicts-r-u.json`

**Interfaces:**
- Consumes: `r-u.json` and R–U entries in the two answer files.
- Produces: verdicts for 52 cases.

- [x] **Step 1: Dispatch a fresh agent**

Agent tool, `subagent_type: "general-purpose"`, `model: "sonnet"`,
`description: "Verify R-U claims"`:

```
You are fact-checking claims written for a QA test document. Another agent
wrote them. Your job is to find the ones that are wrong.

A QA engineer will read these claims while deciding whether RocketVault is
behaving correctly. A claim that sounds right but is not sends them to file
a defect against working software, or to sign off a broken build. This
group covers master key rotation and disaster recovery, where acting on a
wrong claim destroys data that cannot be recovered. You are the last check
before that.

Check these files -- every field in every case whose id starts with R, S, T
or U:
- /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/r-u.json
- /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/answers-cli.json   (R-U entries only)
- /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/answers-authz.json (R-U entries only)

For EVERY why, verify and after field, open its cited source and decide
whether that source actually says what the claim says.

  supported    -- the citation says this. Ships.
  overstated   -- related but weaker than the claim. Say what the citation
                  actually supports.
  contradicted -- the citation says something else. Quote it.
  not-found    -- the cited section or line does not exist, or does not
                  discuss this.

Sources:
- "VAULT_USER_ACCESS_JOURNEYS_v3.md § <section>" -- open
  /home/numericlabs/data/rocket/rocketvault/docs/VAULT_USER_ACCESS_JOURNEYS_v3.md
- "path/to/file.go:214" -- open that file at that line.

Be adversarial. Four claims in this group carry more weight than the rest,
and each is a place where an approximately-right sentence is dangerous:

- Journey R: that a backup restored after a master key rotation is
  unrecoverable without the PRE-rotation key, because the values inside
  are column-level ciphertext sealed under it, independent of the file
  wrapper. A claim that softens "no recovery path" into something
  conditional is overstated -- flag it.
- Journey S: that anything other than the exact string "yes", INCLUDING A
  BLANK LINE, prints "Aborted." and EXITS 0. Check the exit code claim
  specifically. A claim that says it exits non-zero is contradicted, and
  would tell a tester their maintenance script is safe when it is not.
- Journey S: that nothing in the code stops master-key rotation running
  against a live server.
- Journey T: the ROCKETVAULT_VAULT divergence -- vault-access reads it,
  secrets does not. Check that direction. Reversed, it is exactly as wrong
  as nonsense and reads perfectly naturally.

Also:
- A claim that is TRUE but not supported by ITS OWN citation is
  "not-found", not "supported".
- Any hedging word -- "should", "presumably", "likely", "appears to" --
  is a rule violation regardless of truth. Report it as overstated. In
  this group especially: a hedged warning about unrecoverable data loss
  is worse than no warning, because it reads as caution rather than fact.
- Check every related[].id exists as a case id in
  /home/numericlabs/data/rocket/rocketvault/journeybook/src/data/.

Write your verdicts, keyed "<case-id>.<field>", to:
/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/verdicts-r-u.json

with the shape {"verdict": "...", "note": "...", "supported_claim": "..."}
where note and supported_claim apply to non-supported verdicts.

Do not edit any other file. Report only.

Report back: counts per verdict, every non-supported field in full, and a
separate explicit statement of what you found for each of the four
high-weight claims listed above.
```

- [x] **Step 2: Read the four high-weight findings yourself**

```bash
cd /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich
bun -e "
  const v = JSON.parse(require('fs').readFileSync('verdicts-r-u.json','utf8'))
  const bad = Object.entries(v).filter(([,x]) => x.verdict !== 'supported')
  console.log(Object.keys(v).length + ' fields, ' + bad.length + ' not supported')
  for (const [k, x] of bad) console.log(k + '  ' + x.verdict + '  ' + (x.note ?? ''))
"
```

Then open `docs/VAULT_USER_ACCESS_JOURNEYS_v3.md` at the Journey S scripting
trap (around line 1420) and read it against whatever the S cases now claim.
This is the one claim in the whole book where being wrong causes a tester to
certify a maintenance job that silently did nothing, and it is cheap to check
by hand.

---

### Task 2: Verify journeys V–W

**Files:**
- Create: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/verdicts-v-w.json`

**Interfaces:**
- Consumes: `v-w.json` and V–W entries in the two answer files.
- Produces: verdicts for 32 cases.

- [x] **Step 1: Dispatch a fresh agent**

Agent tool, `subagent_type: "general-purpose"`, `model: "sonnet"`,
`description: "Verify V-W claims"`:

```
You are fact-checking claims written for a QA test document. Another agent
wrote them. Your job is to find the ones that are wrong.

A QA engineer will read these claims while deciding whether RocketVault is
behaving correctly. A claim that sounds right but is not sends them to file
a defect against working software, or to sign off a broken build. You are
the last check before that.

Check these files -- every field in every case whose id starts with V or W:
- /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/v-w.json
- /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/answers-cli.json   (V-W entries only)
- /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/answers-authz.json (V-W entries only)

For EVERY why, verify and after field, open its cited source and decide
whether that source actually says what the claim says.

  supported    -- the citation says this. Ships.
  overstated   -- related but weaker than the claim. Say what the citation
                  actually supports.
  contradicted -- the citation says something else. Quote it.
  not-found    -- the cited section or line does not exist, or does not
                  discuss this.

Sources:
- "VAULT_USER_ACCESS_JOURNEYS_v3.md § <section>" -- open
  /home/numericlabs/data/rocket/rocketvault/docs/VAULT_USER_ACCESS_JOURNEYS_v3.md
- "path/to/file.go:214" -- open that file at that line.

Be adversarial. One claim in this group matters more than all the others:

- Journey W turns on an ASYMMETRY. A global (vault_id NULL) scoped DENY
  still matches every vault. A global scoped ALLOW matches none. Check
  the direction of EVERY W claim that touches this. The symmetric version
  -- "a NULL scope matches everything" or "matches nothing", applied to
  both -- reads more naturally than the truth and is what a careless
  writer produces. Cross-check against
  /home/numericlabs/data/rocket/rocketvault/docs/release-notes/v4.6.0-narrow-global-vault-manage.md
  as well as the journeys document. If a claim has this backwards, that is
  contradicted, and say so loudly in your report: it would tell a tester
  an access-control boundary works the opposite of how it does.

Also:
- Journey V's non-delegability reasoning: a principal able to amend its
  own provisioning grant could raise its own quota. Check that the claim
  matches this, and does not merely say "admins only".
- A claim that is TRUE but not supported by ITS OWN citation is
  "not-found", not "supported".
- Any hedging word is a rule violation regardless of truth. Report it as
  overstated.
- Check every related[].id exists as a case id in
  /home/numericlabs/data/rocket/rocketvault/journeybook/src/data/.

Write your verdicts, keyed "<case-id>.<field>", to:
/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/verdicts-v-w.json

with the shape {"verdict": "...", "note": "...", "supported_claim": "..."}
where note and supported_claim apply to non-supported verdicts.

Do not edit any other file. Report only.

Report back: counts per verdict, every non-supported field in full, and an
explicit statement of what you found on the W allow/deny asymmetry.
```

- [x] **Step 2: Check the asymmetry by hand**

Run the summary script from Task 1 Step 2 against `verdicts-v-w.json`.

Then read every W claim mentioning `NULL` scope yourself, against
`docs/release-notes/v4.6.0-narrow-global-vault-manage.md`. Two agents have now
touched this fact and both could mirror it the same way — the version that
reads naturally is the wrong one, which is exactly the shape of error that
survives review. Confirm: **deny matches every vault, allow matches none.**

---

### Task 3: Apply every verdict

**Files:**
- Modify: all six enrichment JSON files and both answer files, in the scratchpad
- Create: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/cuts.md`

**Interfaces:**
- Consumes: the five verdict files.
- Produces: enrichment files containing only supported claims, and a record of what was removed.

- [x] **Step 1: Summarise the whole run**

```bash
cd /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich
bun -e "
  const fs = require('fs')
  const files = ['verdicts-a-f.json','verdicts-g-m.json','verdicts-n-q.json','verdicts-r-u.json','verdicts-v-w.json']
  const tally = {}
  const bad = []
  for (const f of files)
    for (const [k, x] of Object.entries(JSON.parse(fs.readFileSync(f,'utf8')))) {
      tally[x.verdict] = (tally[x.verdict] ?? 0) + 1
      if (x.verdict !== 'supported') bad.push([f, k, x])
    }
  console.log(tally)
  for (const [f, k, x] of bad) console.log(f + '  ' + k + '  ' + x.verdict + '  ' + (x.note ?? ''))
"
```

- [x] **Step 2: Apply each verdict to the enrichment files**

Work through every non-supported field:

- **`overstated`** — rewrite the field down to the verifier's
  `supported_claim`. If that leaves nothing worth saying, delete the field.
- **`contradicted`** — delete the field. Record it.
- **`not-found`** — delete the field. Record it.

Write `cuts.md` as you go, one line per removal: case id, field, verdict, and
the verifier's note. This file is the evidence that the gates ran, and plan 09
reads it during the final review.

Delete the `needs-code` arrays too — they have all been through plan 06 by
now, and leaving them would make the merge script report resolved questions as
open.

- [x] **Step 3: Take the contradictions to the human**

A `contradicted` verdict is not a writing mistake. It means a claim traceable
to a source disagrees with that source, which is either doc rot in
`VAULT_USER_ACCESS_JOURNEYS_v3.md` or a real defect in RocketVault. Both need
a human.

Present each one: the case, the claim as written, the citation, and what the
citation actually says. Add them to the Decisions section of `questions.md`
alongside plan 06's disagreements.

If there were none, say so explicitly. "Nothing to report" is information;
its absence is indistinguishable from a step that was skipped.

- [x] **Step 4: Confirm the files still parse**

```bash
cd /home/numericlabs/data/rocket/rocketvault/journeybook
for f in j a-f g-m n-q r-u v-w answers-cli answers-authz; do
  bun scripts/apply-enrichment.mjs --dry-run \
    /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/$f.json || echo "FAILED: $f"
done
```

Expected: eight clean dry runs, no `unresolved` lines left in any of them, and
`git diff --stat` still empty.

---

## When this plan is complete

```bash
cd /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich && ls && wc -l cuts.md
cd /home/numericlabs/data/rocket/rocketvault && git status --short journeybook/
```

Expected: eight enrichment files carrying only supported claims, five verdict
files, `questions.md` with its Decisions section, `cuts.md` recording every
removal, and still no modified data file.

**Next plan:** `docs/superpowers/plans/2026-09-06-journeybook-detail-09-apply.md`

---

## Self-Review

**Spec coverage:** groups 4 and 5 of phase 3, plus the spec's rule that only
`supported` ships and that `contradicted`/`not-found` are reported rather than
silently dropped — Task 3 Steps 2 and 3.

**Placeholder scan:** none. Both prompts are final text. Task 3 Step 2 is
judgment work rather than a command, and says exactly what to do for each of
the three verdicts rather than "apply the feedback".

**Type consistency:** verdict keys stay `<case-id>.<field>`, matching plan 07.
Task 3 Step 2's deletion of `needs-code` keeps the enrichment files valid
against `properties()` in plan 01 Task 2, which treats the key as optional.

**Known risk:** Task 3 is the only place a claim can be removed, which makes it
a single point of failure — a field that should have been cut and was not
ships. That is deliberate rather than accidental: spreading cuts across five
tasks would make it impossible to see, in one diff, everything that left the
set. `cuts.md` exists so the decision is auditable after the fact.
