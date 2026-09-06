# Enrichment brief

You are adding detail to RocketVault's QA journeybook. A QA engineer opens
this page offline and records a pass or fail against each check. Today a check
carries a title, one assertion, a command and an expected line. You are adding
the reasoning the source document has and the page dropped.

**The thing that matters more than coverage: a check that misleads a tester is
worse than a thin one.** A thin check sends them to the document. A confidently
wrong one sends them to file a defect against working software, or to pass a
broken build. Every rule below exists for that reason.

## What you produce

One JSON file, keyed by case id. Nothing else. **Do not edit any file under
`journeybook/src/data/`** — five agents writing four files concurrently
corrupts them.

```json
{
  "B3": {
    "why":    { "text": "...", "source": "..." },
    "verify": { "command": "...", "look": "...", "source": "..." },
    "after":  { "text": "...", "source": "..." },
    "related": [{ "id": "B2", "rel": "depends" }],
    "needs-code": ["why: <the precise open question>"]
  }
}
```

Every key is optional. A case with nothing worth adding gets no entry at all.

This shape is **validated** by `scripts/apply-enrichment.mjs` before anything
is applied: `why` and `after` must be objects with a string `text`; `verify`
must be an object with a string `look`; `related` must be an array of objects
with a string `id` and a `rel` that is one of `depends`/`diverges`/`contrasts`;
`needs-code` must be an array of strings. A bare string where an object is
expected fails the run and names your file.

## The fields

**`why`** — the mechanism. Why the system behaves this way, not what the
command does. "`HasDataAction` has no admin short-circuit, so creating a vault
grants nothing inside it" is a why. "This command lists keys" is not.

**`verify`** — how to settle pass from fail when `expected` leaves a margin.
`look` is required; `command` is optional. Add it only where the expected line
genuinely leaves room for doubt, not on every case.

**`after`** — what the check leaves behind, and what to undo before the next
one. Most checks leave nothing; most cases get no `after`.

**`related`** — cross-references. `depends` (this check is meaningless unless
that one passed first), `diverges` (the same authority gives a different answer
there), `contrasts` (the neighbouring case with the opposite outcome). Only
real, useful links. Two or three across a journey beats one on every case.
Every `id` must be a real case id — a dangling one fails the build.

**`needs-code`** — open questions you could not settle from the documents.
Phrase each as `field: the precise question`. These do not block the fields
beside them: a case can carry a finished `why` and an open `verify` question at
once.

## The five gates

**1. Provenance or nothing.** Every `why`, `verify` and `after` carries a
`source`: a document section (`VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J —
the purge trap`) or a code location (`internal/services/vaults/vault_service.go:214`).
If you cannot cite it, do not write it. **Omission is a correct outcome.** An
absent `why` is honest; a plausible-sounding invented one is the failure this
brief exists to prevent.

**2. No invented commands.** A `verify.command` is transcribed verbatim from
the document, or built only from flags you have confirmed exist by reading the
cobra registration in `cmd/`. Never inferred from a flag name, never guessed
from a pattern in a neighbouring command. If you cannot confirm it, ship `look`
prose with no command and raise a `needs-code` question.

**3. You will be checked.** A different agent re-opens every citation you write
and reports whether it supports your claim, overstates it, contradicts it, or
does not exist. Only supported claims ship. Write accordingly.

This is not a formality. The pilot journey was authored by hand with care, and
the audit still found two clauses that went past their own citation — one of
them self-contradicting a neighbouring field. Both were cut. Expect the same
scrutiny.

**4. Doc/code disagreement is surfaced, never resolved.** The journeys document
is dated and the CLI has drifted before. If the document says one thing and the
code says another, **do not pick a winner and do not write the code's answer
into the case.** Record both in a `needs-code` entry prefixed `DISAGREEMENT:`
and move on. A case quietly corrected from source contradicts the document the
tester has open beside it, and it hides what may be a real bug or real doc rot.

**5. No hedging.** No "should", "presumably", "likely", "appears to", "is
expected to". A claim you cannot state flatly from a source is not written.
Hedged text reads as information while carrying none, and a tester cannot act
on it.

## Style

- The audience is a QA engineer mid-run, not a developer reading a design doc.
  Plain sentences. No filler.
- Two inline markers render, and nothing else: `` `code` `` and `**bold**`.
  Anything else appears literally, deliberately, so a real error message
  containing an asterisk is not silently eaten.
- Keep `why` to one to four sentences. If it needs more, you are explaining the
  subsystem rather than the check.
- Do not restate the case's own `assert` as a `why`. The assert says what the
  outcome is; the why says what produces it.
- Where an existing `notes` already carries the mechanism, put that half in
  `why` and add a `needs-code` entry saying which `notes` needs its mechanism
  half removed. **Do not duplicate**, and never propose dropping the actionable
  half of a note.

## The worked example

`journeybook/src/data/journeys-g-m.ts`, Journey J, is the reference. Read all
seven cases there — the shipped data, not any plan document — before you start.
Three things in it are precedent:

- **J2 carries no `why`.** The document shows its command and does not explain
  it. Inferring a reason from the flag name would be a Gate 1 violation. This
  is the single most important line in the example.
- **J1 and J4 carry `needs-code` beside finished fields.**
- **J5's `why` cites Journey K**, because that is where the fact actually is.
  Cite where the claim lives, not where the case sits.
