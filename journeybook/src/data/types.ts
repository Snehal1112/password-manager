/**
 * The shape of the playbook.
 *
 * Every field here is transcribed from docs/VAULT_USER_ACCESS_JOURNEYS_v3.md.
 * Commands and expected output are copied, never paraphrased and never
 * invented -- if the doc says a capability has no CLI command, the case says
 * so too. See .claude/authoring-cases.md before adding anything.
 */

/** Which authorization gate a case is written to exercise. */
export type Gate =
  /** The CLI-only global role gate, Correction 8. No HTTP equivalent. */
  | "global-role"
  /** An access policy explicit deny, evaluated before any role check. */
  | "explicit-deny"
  /** Deny-by-default per-vault role assignment. Applies to admins too. */
  | "vault-role"
  /** Vault management: CanManageVault / CanPurgeVault / role assignments. */
  | "management"
  /** Admin-only surfaces: audit, access policies, backup, master key. */
  | "global-admin"
  /** Flag parsing and request validation, before any authorization runs. */
  | "validation"
  /** No gate: the case asserts ordinary behaviour, not a denial. */
  | "none"

/** Which door the tester walks through. */
export type Surface = "cli" | "http" | "both" | "db" | "local"

/**
 * How one check relates to another. Three values rather than a free string,
 * because a tester scanning a cross-reference needs to know which kind it is:
 * `depends` means this check is meaningless unless that one passed first,
 * `diverges` means the same authority produces a different answer there
 * (Journey K's CLI/HTTP purge split is the archetype), and `contrasts` is the
 * neighbouring case showing the opposite outcome -- usually the allow beside
 * the deny.
 */
export type Relation = "depends" | "diverges" | "contrasts"

export interface Related {
  /** Must resolve to a real case id. scripts/check-links.mjs enforces it. */
  id: string
  rel: Relation
}

/**
 * How to settle pass from fail when `expected` leaves a margin.
 *
 * One object, not an array. Rule 3 of .claude/authoring-cases.md is one
 * assertion per case, so a check needing two independent verifications is two
 * checks.
 */
export interface Verify {
  /**
   * Transcribed from the journeys doc, or built only from flags confirmed to
   * exist by reading the cobra registration in cmd/. Never inferred: a
   * verification command carrying a flag that does not exist wastes a
   * tester's time and teaches them to distrust the page.
   */
  command?: string
  /** What in the result settles it. Required whenever `verify` is present. */
  look: string
}

export interface Case {
  /** Stable across edits -- verdicts are keyed on it in localStorage. */
  id: string
  title: string
  surface: Surface
  gate: Gate
  /** State the instance must be in. Omit when the suite preamble covers it. */
  precondition?: string
  /** Verbatim from the doc. Multi-line shell is fine. */
  command: string
  /** Verbatim expected output, including the exact error string. */
  expected: string
  /**
   * The short assertion shown on the collapsed row -- what a tester scans for
   * when deciding whether the run matched. Keep it to a few words.
   */
  assert: string
  /** Why the case exists, or what is easy to get wrong. Light markdown. */
  notes?: string
  /** Marks a documented divergence, gap, or trap rather than a happy path. */
  flag?: "divergence" | "gap" | "trap"
  /**
   * The mechanism. Why the system behaves this way, not what the command
   * does. A tester whose run does not match needs something to reason with.
   *
   * Requires `source`. An absent `why` is honest; an invented one is the
   * failure mode the whole enrichment exists to avoid.
   */
  why?: string
  /** How to settle pass from fail. Requires `source`. */
  verify?: Verify
  /** What this leaves behind, and what to undo first. Requires `source`. */
  after?: string
  /** Other checks this one leans on or contradicts. */
  related?: Related[]
  /**
   * Provenance for `why`, `verify` and `after`. Either a document section
   * (`VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J -- the purge trap`) or a
   * code location (`internal/services/vaults/vault_service.go:214`). Several
   * citations are separated by `; `.
   */
  source?: string
}

export interface Suite {
  /** The journey letter, A-U. */
  key: string
  title: string
  actor: string
  /** One or two sentences: what this journey is actually about. */
  premise: string
  /**
   * The journey-level prose the document carries between its command blocks,
   * one string per paragraph. `premise` stays the one-sentence summary shown
   * on the collapsed suite; this is what a tester reads before starting.
   */
  context?: string[]
  cases: Case[]
}
