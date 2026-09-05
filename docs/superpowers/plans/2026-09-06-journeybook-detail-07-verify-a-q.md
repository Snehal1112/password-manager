# Journeybook Detail — Verify A–Q — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adversarially verify every claim written for journeys A–Q by re-opening its citation, and record a verdict per field.

**Architecture:** Gate 3. The agent verifying a group is never the agent that wrote it, and it is given the claim and the citation rather than the document as a whole — its job is to answer "does this source say this", not "is this plausible". Plausible is how a wrong claim survives.

**Tech Stack:** Agent tool with Sonnet. Checking a claim against a named citation is a narrower task than producing the claim was.

**Spec:** `docs/superpowers/specs/2026-09-06-journeybook-case-detail-design.md`

**Prerequisite:** Plan 06 complete, including the human decisions on every disagreement.

**Followed by:** `2026-09-06-journeybook-detail-08-verify-r-w.md`.

## Global Constraints

- **A verifier must never have written the work it checks.** Dispatch a fresh agent for each group. Do not reuse an extraction agent by sending it a follow-up message — it has its own output in context and will defend it.
- Four verdicts only: `supported`, `overstated`, `contradicted`, `not-found`. Only `supported` ships.
- `contradicted` and `not-found` are **reported**, not silently dropped. Either can mean a real defect in the journeys document rather than a bad citation.
- Verifiers write verdict files. They do not edit enrichment files and they do not edit `journeybook/src/data/`. Plan 08 Task 3 applies the cuts, once, in one place.
- Scratchpad root: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/`

---

### Task 1: Verify journeys A–F

**Files:**
- Create: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/verdicts-a-f.json`

**Interfaces:**
- Consumes: `a-f.json`, plus any A–F fields in `answers-cli.json` and `answers-authz.json`.
- Produces: one verdict per field, keyed `<case-id>.<field>`.

- [ ] **Step 1: Dispatch a fresh agent**

Agent tool, `subagent_type: "general-purpose"`, `model: "sonnet"`,
`description: "Verify A-F claims"`:

```
You are fact-checking claims written for a QA test document. Another agent
wrote them. Your job is to find the ones that are wrong.

A QA engineer will read these claims while deciding whether RocketVault is
behaving correctly. A claim that sounds right but is not sends them to file
a defect against working software, or to sign off a broken build. You are
the last check before that.

Check these files -- every field in every case whose id starts with A, B, C,
D, E or F:
- /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/a-f.json
- /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/answers-cli.json   (A-F entries only)
- /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/answers-authz.json (A-F entries only)

For EVERY why, verify and after field, open its cited source and decide
whether that source actually says what the claim says.

  supported    -- the citation says this. Ships.
  overstated   -- the citation is related but weaker than the claim. Say
                  what the citation actually supports, so it can be
                  rewritten down to that.
  contradicted -- the citation says something else. Quote what it says.
  not-found    -- the cited section or line does not exist, or exists and
                  does not discuss this at all.

Sources you will encounter:
- "VAULT_USER_ACCESS_JOURNEYS_v3.md § <section>" -- open
  /home/numericlabs/data/rocket/rocketvault/docs/VAULT_USER_ACCESS_JOURNEYS_v3.md
  and find that section. If the section does not exist, that is not-found.
- "path/to/file.go:214" -- open that file at that line.

Be adversarial. Specifically:

- A claim that is TRUE but not supported by ITS OWN citation is
  "not-found", not "supported". The citation is the contract. Something
  being true elsewhere does not make this citation correct.
- Check direction on anything involving allow/deny, before/after, or
  CLI/HTTP. A mirror-imaged claim reads perfectly naturally and is exactly
  as wrong as a nonsense one.
- Check that hedging is absent. Any "should", "presumably", "likely",
  "appears to" is a rule violation regardless of whether the claim is
  true; report it as overstated.
- Check every related[].id actually appears as a case id somewhere in
  /home/numericlabs/data/rocket/rocketvault/journeybook/src/data/. A
  dangling id renders as a plausible case number a tester goes hunting
  for.

Write your verdicts to:
/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/verdicts-a-f.json

{
  "A7.why":    { "verdict": "supported" },
  "B3.verify": { "verdict": "overstated",
                 "note": "The doc says Reader cannot read values. It does not say the versions list omits the field; that is stated in the B30 regression check.",
                 "supported_claim": "Reader has no secrets/get, so the value is not returned." },
  "C12.why":   { "verdict": "not-found",
                 "note": "There is no section 'Journey C -- rotation ceiling' in the document." }
}

Do not edit any other file. Do not fix anything -- report only. Somebody
else applies the cuts, and a verifier that edits loses the record of what
was wrong.

Report back: counts per verdict, and every non-supported field in full.
```

- [ ] **Step 2: Read the non-supported findings yourself**

```bash
cd /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich
bun -e "
  const v = JSON.parse(require('fs').readFileSync('verdicts-a-f.json','utf8'))
  const bad = Object.entries(v).filter(([,x]) => x.verdict !== 'supported')
  console.log(Object.keys(v).length + ' fields, ' + bad.length + ' not supported')
  for (const [k, x] of bad) console.log(k + '  ' + x.verdict + '  ' + (x.note ?? ''))
"
```

A group coming back 100% supported is not good news — it means the verifier
agreed with everything, which is what a verifier does when it is reading for
plausibility rather than opening citations. Spot-check two `supported`
verdicts by opening the citation yourself. If either is wrong, re-dispatch
with a note that the first pass rubber-stamped.

---

### Task 2: Verify journeys G–M, including the pilot

**Files:**
- Create: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/verdicts-g-m.json`

**Interfaces:**
- Consumes: `g-m.json`, `j.json`, and G–M entries in the two answer files.
- Produces: verdicts for 50 cases, Journey J included.

**Journey J is verified here, not exempted.** It was authored by hand and is
the exemplar the other four groups copied, which makes an unchecked error in
it the most expensive kind. Authorship is not a reason to skip a check; it is
a reason to want one.

- [ ] **Step 1: Dispatch a fresh agent**

Agent tool, `subagent_type: "general-purpose"`, `model: "sonnet"`,
`description: "Verify G-M claims"`:

```
You are fact-checking claims written for a QA test document. Other agents
wrote them. Your job is to find the ones that are wrong.

A QA engineer will read these claims while deciding whether RocketVault is
behaving correctly. A claim that sounds right but is not sends them to file
a defect against working software, or to sign off a broken build. You are
the last check before that.

Check these files -- every field in every case whose id starts with G, H, I,
J, K, L or M:
- /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/g-m.json
- /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/j.json
- /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/answers-cli.json   (G-M entries only)
- /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/answers-authz.json (G-M entries only)

j.json was written by hand and was the example the other groups copied.
Check it exactly as hard as the rest -- an error there propagated.

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

Be adversarial. Specifically:

- A claim that is TRUE but not supported by ITS OWN citation is
  "not-found", not "supported".
- Journey K is a CLI/HTTP divergence and Journey H is about evaluation
  ORDER. Both are places where a mirror-imaged claim reads perfectly
  naturally and is exactly as wrong as a nonsense one. Check direction on
  every one.
- J5 claims the CLI vaults purge path has an admin bypass in
  CanPurgeVault that the HTTP route does not have, cited to Journey K.
  Verify that citation specifically and say what you find.
- Any hedging word -- "should", "presumably", "likely", "appears to" --
  is a rule violation regardless of truth. Report it as overstated.
- Check every related[].id exists as a case id in
  /home/numericlabs/data/rocket/rocketvault/journeybook/src/data/.

Write your verdicts, keyed "<case-id>.<field>", to:
/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/verdicts-g-m.json

with the shape {"verdict": "...", "note": "...", "supported_claim": "..."}
where note and supported_claim apply to non-supported verdicts.

Do not edit any other file. Report only -- somebody else applies the cuts.

Report back: counts per verdict, and every non-supported field in full.
```

- [ ] **Step 2: Read the findings, and read J's verdicts first**

Run the same summary script from Task 1 Step 2 against `verdicts-g-m.json`.

Then look specifically at every `J*` verdict. If J's own claims did not
survive, the four groups that copied its shape need re-examining too, and that
is a decision to take to the human before continuing rather than after.

---

### Task 3: Verify journeys N–Q

**Files:**
- Create: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/verdicts-n-q.json`

**Interfaces:**
- Consumes: `n-q.json` and N–Q entries in the two answer files.
- Produces: verdicts for 47 cases.

- [ ] **Step 1: Dispatch a fresh agent**

Agent tool, `subagent_type: "general-purpose"`, `model: "sonnet"`,
`description: "Verify N-Q claims"`:

```
You are fact-checking claims written for a QA test document. Another agent
wrote them. Your job is to find the ones that are wrong.

A QA engineer will read these claims while deciding whether RocketVault is
behaving correctly. A claim that sounds right but is not sends them to file
a defect against working software, or to sign off a broken build. You are
the last check before that.

Check these files -- every field in every case whose id starts with N, O, P
or Q:
- /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/n-q.json
- /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/answers-cli.json   (N-Q entries only)
- /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/answers-authz.json (N-Q entries only)

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

Be adversarial. Specifically:

- A claim that is TRUE but not supported by ITS OWN citation is
  "not-found", not "supported".
- Journey N is multi-vault isolation, where three different 403s mean
  three different things. A claim naming the wrong gate is contradicted,
  not supported, even though the outcome it describes is right.
- Journey P turns on secrets rotation checking NO global role. That
  absence is the mechanism. A claim that inverts it -- saying a role IS
  required -- is contradicted.
- Any hedging word -- "should", "presumably", "likely", "appears to" --
  is a rule violation regardless of truth. Report it as overstated.
- Check every related[].id exists as a case id in
  /home/numericlabs/data/rocket/rocketvault/journeybook/src/data/.

Write your verdicts, keyed "<case-id>.<field>", to:
/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/verdicts-n-q.json

with the shape {"verdict": "...", "note": "...", "supported_claim": "..."}
where note and supported_claim apply to non-supported verdicts.

Do not edit any other file. Report only -- somebody else applies the cuts.

Report back: counts per verdict, and every non-supported field in full.
```

- [ ] **Step 2: Read the findings**

Run the summary script from Task 1 Step 2 against `verdicts-n-q.json`, and
spot-check two `supported` verdicts by opening the citations yourself.

---

## When this plan is complete

```bash
ls /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/verdicts-*.json
cd /home/numericlabs/data/rocket/rocketvault && git status --short journeybook/
```

Expected: three verdict files, and still no modified data file. Nothing is cut
and nothing is applied until plan 08 Task 3 and plan 09.

**Next plan:** `docs/superpowers/plans/2026-09-06-journeybook-detail-08-verify-r-w.md`

---

## Self-Review

**Spec coverage:** groups 1, 2 and 3 of the spec's phase 3, using the spec's
four-verdict table verbatim.

**Placeholder scan:** none. All three prompts are final text.

**Type consistency:** verdict keys are `<case-id>.<field>` where field is one
of `why`, `verify`, `after` — matching the `Case` fields from plan 01 Task 1
that carry claims. `related` is checked but has no verdict of its own; a
dangling id is reported in prose and caught mechanically by `check:links` in
plan 09.

**Known risk:** a verifier rubber-stamping is the failure mode that defeats
this entire phase, and it produces output indistinguishable from a clean pass.
That is why Task 1 Step 2 treats 100% supported as a signal to spot-check
rather than a result to accept, and why the spot-check is done by hand rather
than delegated to a sixth agent — an agent checking an agent that checked an
agent adds a layer without adding a source.
