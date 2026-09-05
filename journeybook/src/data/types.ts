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
}

export interface Suite {
  /** The journey letter, A-U. */
  key: string
  title: string
  actor: string
  /** One or two sentences: what this journey is actually about. */
  premise: string
  cases: Case[]
}
