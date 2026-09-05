# Journeybook Detail — The Code Pass — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve every `needs-code` question the five extraction agents raised, by reading `cmd/` and `internal/`, with a `file.go:line` citation on each answer — and put every doc/code disagreement in front of a human.

**Architecture:** Two Opus agents, split by the kind of reasoning each question needs rather than by journey: one answers "does this command or flag exist and what exactly does it do", which is cobra registration reading; the other answers "why does authorization decide this way", which means following the two-stage check through the service layer. Splitting by question type keeps each agent in one part of the tree.

**Tech Stack:** Agent tool with **Opus**. This is the one phase that reasons about Go authorization paths rather than transcribing prose, and it is the phase whose output is hardest to check by eye — a wrong `file.go:214` looks exactly like a right one.

**Spec:** `docs/superpowers/specs/2026-09-06-journeybook-case-detail-design.md`

**Prerequisite:** Plans 04 and 05 complete; six JSON files in the scratchpad.

**Followed by:** `2026-09-06-journeybook-detail-07-verify-a-q.md`.

## Global Constraints

- **Gate 4 is the whole reason this plan has a stop in it.** An agent that finds the code disagreeing with `VAULT_USER_ACCESS_JOURNEYS_v3.md` records both and stops. It does not write the code's answer into a case. A case quietly corrected from source contradicts the document the tester has open beside it, and hides what may be a real bug or real doc rot.
- Every answer carries a `file.go:line` citation. An answer without one is not an answer.
- **No subagent writes to `journeybook/src/data/`.** Answers go into a new JSON file; plan 09 merges everything.
- A question that cannot be settled from the code is closed as unresolved, and its field is dropped. Omission is a correct outcome — that is Gate 1, and it applies to this phase exactly as it applied to phase 1.

---

### Task 1: Collate the open questions

**Files:**
- Create: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/questions.md`

**Interfaces:**
- Consumes: the `needs-code` arrays in all six scratchpad JSON files.
- Produces: one worklist, split into the two buckets Tasks 2 and 3 consume.

- [ ] **Step 1: Extract every open question**

```bash
cd /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich
for f in j.json a-f.json g-m.json n-q.json r-u.json v-w.json; do
  echo "=== $f"
  bun -e "
    const d = JSON.parse(require('fs').readFileSync('$f','utf8'))
    for (const [id, e] of Object.entries(d))
      for (const q of e['needs-code'] ?? []) console.log(id + '  ' + q)
  "
done
```

- [ ] **Step 2: Write the worklist, split by question type**

Create `questions.md` with two sections. Sort each question into exactly one:

- **Commands and flags** — "does this flag exist", "what is the command for
  X", "what is the exact error string". Answered by reading `cmd/`.
- **Authorization and behaviour** — "why is this denied", "which check fires
  first", "what does this service actually do on purge". Answered by reading
  `internal/services/` and `model/`.

Anything prefixed `DISAGREEMENT:` goes in a **third** section, untouched. Those
are not questions for an agent; they are for a human, in Task 3 Step 2.

Format each line as `<case-id>  <field>: <question>` so an agent can key its
answer back.

---

### Task 2: Answer the command and flag questions

**Files:**
- Create: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/answers-cli.json`

**Interfaces:**
- Consumes: the "Commands and flags" section of `questions.md`.
- Produces: the same JSON shape as an extraction file, containing only the fields the answers fill in. Plan 09 merges it alongside the rest.

- [ ] **Step 1: Dispatch**

Agent tool, `subagent_type: "general-purpose"`, `model: "opus"`,
`description: "Resolve CLI command questions"`:

```
You are settling open questions about RocketVault's CLI, for a QA
journeybook. Each answer you write will be read by a QA engineer who will
type the command you describe. A command that does not exist, or a flag
spelled wrong, wastes their time and teaches them to distrust the page.

Read first:
1. /home/numericlabs/data/rocket/rocketvault/journeybook/.claude/enrichment-brief.md
   -- the rules, which bind you exactly as they bound the extraction agents.
   Gates 1, 2, 4 and 5 are the ones that will bite here.
2. /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/questions.md
   -- answer ONLY the questions under "Commands and flags".

Your source of truth is the code in
/home/numericlabs/data/rocket/rocketvault/cmd/. Read the actual cobra
command and flag registration. Do not infer a flag from a neighbouring
command's flags, from a help string, or from documentation -- those drift,
and the registration does not.

For each question, produce one of exactly three outcomes:

  ANSWERED   -- you found it. Write the field text, and cite the exact
                file and line: cmd/secrets/restore.go:41
  UNRESOLVED -- the code does not settle it. Say so. The field gets
                dropped. This is a correct outcome, not a failure.
  DISAGREEMENT -- the code contradicts what
                docs/VAULT_USER_ACCESS_JOURNEYS_v3.md says. Record BOTH
                the document's claim and the code's behaviour with its
                citation, and DO NOT write either into a case. A human
                decides. Do not resolve it yourself.

Write ANSWERED outcomes to:
/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/answers-cli.json

in the same shape the extraction files use, keyed by case id -- for example:

{
  "J4": {
    "after": {
      "text": "Restore it with `rocketvault secrets restore <secret-id> --vault staging` before continuing.",
      "source": "cmd/secrets/restore.go:41"
    }
  }
}

Include only fields you are ANSWERING. Do not restate fields the extraction
agents already wrote. Do not edit any file under journeybook/src/data/.

Report back, in your final message: every ANSWERED question with its
citation, every UNRESOLVED one, and every DISAGREEMENT in full. The last
group goes to a human, so quote both sides exactly.
```

- [ ] **Step 2: Spot-check the citations yourself**

Pick three answers at random and open the cited line. A wrong `file.go:214`
looks exactly like a right one in a report, and this is the phase where an
unchecked citation does the most damage — it is the only phase whose claims a
reader cannot check against the journeys document.

```bash
cd /home/numericlabs/data/rocket/rocketvault
# for each of three citations, e.g.:
sed -n '35,50p' cmd/secrets/restore.go
```

Confirm the cited line actually registers the command or flag claimed. If one
of three is wrong, do not spot-check harder — send the whole file back and say
which one failed.

---

### Task 3: Answer the authorization questions, and take disagreements to a human

**Files:**
- Create: `/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/answers-authz.json`

**Interfaces:**
- Consumes: the "Authorization and behaviour" section of `questions.md`.
- Produces: `answers-authz.json`, and a decision from a human on every disagreement.

- [ ] **Step 1: Dispatch**

Agent tool, `subagent_type: "general-purpose"`, `model: "opus"`,
`description: "Resolve authorization questions"`:

```
You are settling open questions about RocketVault's authorization
behaviour, for a QA journeybook. Each answer explains to a QA engineer why
a check passes or fails. Getting one backwards would tell them an
access-control boundary works the opposite of how it does, which is the
worst error this document can contain.

Read first:
1. /home/numericlabs/data/rocket/rocketvault/journeybook/.claude/enrichment-brief.md
   -- the rules. Binding.
2. /home/numericlabs/data/rocket/rocketvault/CLAUDE.md, the Authorization
   and CLI Authorization sections -- they describe the two-stage check and
   the three CLI authorization tiers, and will orient you before you read
   any Go.
3. /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/questions.md
   -- answer ONLY the questions under "Authorization and behaviour".

Your sources of truth, in this order:
- internal/services/authorization/ -- RBACService, AccessPolicyService,
  RoleAssignmentService, and the CanManageVault / CanPurgeVault /
  CanManageRoleAssignments helpers
- model/azure_roles.go -- which built-in role grants which data action
- internal/middleware/ -- what the HTTP path enforces
- cmd/vaultcli/, cmd/vaults/authz.go, cmd/vault-access/authz.go,
  cmd/vault-provisioning/authz.go -- what each CLI tier enforces

The single most common error here is conflating the CLI path with the HTTP
path. They genuinely diverge in more than one place. When you answer, say
which door your answer applies to.

For each question, produce exactly one of:

  ANSWERED     -- with the field text and a file.go:line citation
  UNRESOLVED   -- the code does not settle it; the field is dropped
  DISAGREEMENT -- the code contradicts
                  docs/VAULT_USER_ACCESS_JOURNEYS_v3.md. Record BOTH
                  sides with citations. DO NOT write either into a case.
                  A human decides.

Write ANSWERED outcomes to:
/tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/answers-authz.json

keyed by case id, same shape as the extraction files. Include only fields
you are answering. Do not edit anything under journeybook/src/data/.

Report back: every ANSWERED question with its citation, every UNRESOLVED
one, and every DISAGREEMENT in full with both sides quoted.
```

- [ ] **Step 2: Take every disagreement to the human — this is a stop**

Collect the `DISAGREEMENT` entries from three places: the extraction agents'
reports (plans 04 and 05), Task 2's report, and Task 3 Step 1's report.

For each, present to the human:

- the case id and what it checks
- what `VAULT_USER_ACCESS_JOURNEYS_v3.md` says, quoted
- what the code does, quoted, with its citation
- the three ways forward: the document is stale and should be corrected; the
  code has a bug and the document is right; or both are right and the case is
  ambiguous as written

**Do not choose.** A disagreement between the QA document and the code is
either doc rot or a real defect, and both outcomes need a human who can decide
which. Silently picking one produces a check that contradicts the document a
tester is reading beside it.

If there are no disagreements, say so explicitly rather than skipping the step
— "nothing to report" is information, and its absence is indistinguishable
from a step that was forgotten.

- [ ] **Step 3: Record what the human decided**

Append the decisions to `questions.md` under a **Decisions** heading, each with
the date and what was chosen. Plan 09's final review reads it, and plan 10 may
need to file a follow-up for any code defect found.

---

## When this plan is complete

```bash
ls /tmp/claude-1000/-home-numericlabs-data-rocket-rocketvault/4c18aef0-f336-4049-b9b7-1a2c1359825a/scratchpad/enrich/
cd /home/numericlabs/data/rocket/rocketvault && git status --short journeybook/src/data/
```

Expected: eight files — six extraction, two answers — plus `questions.md`
carrying a Decisions section. No data file modified. Phase 2 complete.

**Next plan:** `docs/superpowers/plans/2026-09-06-journeybook-detail-07-verify-a-q.md`

---

## Self-Review

**Spec coverage:** this is the spec's phase 2 in full, plus Gate 4's escalation
path, which no other plan implements.

**Placeholder scan:** none. Both prompts are final text.

**Type consistency:** both answer files use the extraction JSON shape from the
brief, so plan 09 merges all eight through the same `properties()` function
from plan 01 Task 2. Because the merge script refuses two inputs claiming the
same case id, an answer file must contain only the fields it fills — never a
restatement of one an extraction agent already wrote. Both prompts say so
explicitly.

**Known risk:** an Opus agent asked to settle a question from code will
generally settle it, and the pull toward producing an answer rather than an
UNRESOLVED is the failure mode here — an UNRESOLVED feels like failing the
task. Task 2 Step 2's three-citation spot check is the countermeasure, and it
is deliberately all-or-nothing: one bad citation in three sends the whole file
back, because a sampled error rate that high means the rest are not worth
sampling.
