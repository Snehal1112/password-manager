import type { Suite } from "./types"

export const journeysGM: Suite[] = [
  {
    key: "G",
    title: "Delegating access management without handing over the keys",
    actor: "Wren — global role user, Key Vault Data Access Administrator",
    premise:
      "One role can hand out other roles without ever holding data-plane access itself. The interesting assertions are all about what she cannot do: escalate, revoke her way out, or touch access policies.",
    cases: [
      {
        id: "G1",
        title: "Grant the delegating role",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant wren --role "Key Vault Data Access Administrator" --vault prod`,
        expected: "The assignment is created.",
        assert: "Granted — note Wren's global role is only `user`",
        why: "`vault-access` commands check no global role at all — that is why a bare `user` role is enough for Wren to hold and use this grant.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey G",
      },
      {
        id: "G2",
        title: "She can grant other roles",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant marcus --role "Key Vault Secrets User" --vault prod`,
        expected:
          "granted Key Vault Secrets User to marcus in vault (assignment 8516e7fd-...)",
        assert: "Grant succeeds and returns an assignment id",
        related: [{ id: "G1", rel: "depends" }],
      },
      {
        id: "G3",
        title: "She has zero data-plane access herself",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault secrets list --vault prod`,
        expected: "Error: forbidden: no role grants ... in this vault",
        assert: "Denied — she just granted this to someone else",
        why: "`Key Vault Data Access Administrator` only lets Wren manage role assignments. It carries no data-plane permission of its own, so holding it grants her no access to secrets, keys or certificates.",
        related: [{ id: "G2", rel: "contrasts" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey G (lines 521-527)",
      },
      {
        id: "G4",
        title: "The same denial over HTTP",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' $BASE/vaults/prod/secrets \\
  -H "Authorization: Bearer $WREN_TOKEN"`,
        expected: "403",
        assert: "403",
      },
      {
        id: "G5",
        title: "Self-escalation to Purge Operator is blocked",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant wren --role "Key Vault Purge Operator" --vault prod`,
        expected:
          "Error: grant failed: role cannot be granted by a non-admin caller",
        assert: "ErrRoleNotGrantable — outside the eight-role allow-list",
        why: "Wren can grant only the eight roles the document names: Administrator, Reader, Secrets User, Secrets Officer, Crypto User, Crypto Officer, Certificates Officer, and Crypto Service Encryption User. `Key Vault Purge Operator` is not on that list, so the grant is refused.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey G",
      },
      {
        id: "G6",
        title: "She cannot even re-grant her own role",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant wren --role "Key Vault Data Access Administrator" --vault prod`,
        expected:
          "Error: grant failed: role cannot be granted by a non-admin caller",
        assert: "Denied — Data Access Administrator is not self-grantable",
        why: "`Key Vault Data Access Administrator` is also not among the eight roles Wren can grant — the allow-list she can act on does not include the role she herself holds, so she cannot re-grant it even to herself.",
        related: [{ id: "G9", rel: "contrasts" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey G",
      },
      {
        id: "G7",
        title: "The same allow-list gates revoke",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access revoke <purge-operator-assignment-id> --vault prod`,
        expected: "Error: role cannot be granted by a non-admin caller",
        assert: "No back door via revoke",
        flag: "trap",
        notes: "Check both halves.",
        why: "The same eight-role allow-list gates `revoke`, not just `grant`. Without that, Wren could revoke a role she cannot grant — a privilege change in the opposite direction, such as removing someone else's Purge Operator assignment despite never being able to create one.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey G",
      },
      {
        id: "G8",
        title: "Access policies are a separate, admin-only surface",
        surface: "http",
        gate: "global-admin",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' $BASE/access-policies \\
  -H "Authorization: Bearer $WREN_TOKEN"`,
        expected:
          "403 Insufficient permissions: admin role required to manage access policies",
        assert: "403 with the access-policy-specific message",
        why: "Access policies are a separate surface from role assignments, gated by admin only. `Key Vault Data Access Administrator` covers role assignments alone and does not reach it, so Wren gets 403 here even though she just granted roles under her own authority.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey G (lines 540-543)",
      },
      {
        id: "G9",
        title: "She can grant any of the eight allow-listed roles",
        surface: "cli",
        gate: "management",
        command: `# Administrator, Reader, Secrets User, Secrets Officer, Crypto User,
# Crypto Officer, Certificates Officer, Crypto Service Encryption User`,
        expected: "All eight succeed. The other three roles do not.",
        assert: "Eight succeed, three refuse",
        why: "The allow-list is `nonAdminGrantableRoles`, and it holds exactly those eight. The three built-in roles left out are **Key Vault Data Access Administrator** itself, **Key Vault Purge Operator** and **Key Vault Certificate User** — the last is the one the document does not name. The same list gates revoke as well as grant, so an excluded role cannot be reached from the revoke side either.",
        source:
          "internal/services/authorization/role_assignment_service.go:27-45, :126, :193",
      },
      {
        id: "G10",
        title: "A Secrets User cannot list assignments",
        surface: "cli",
        gate: "management",
        precondition: "Run as marcus, holding only Key Vault Secrets User.",
        command: `rocketvault vault-access list --vault prod`,
        expected: `Error: permission denied: admin, vaults/manage, or Key Vault Data Access
       Administrator required for this vault`,
        assert: "Listing assignments is itself a privileged operation",
        why: "Listing role assignments requires one of three authorities — admin, a `vaults/manage` access policy, or holding `Key Vault Data Access Administrator` in that vault. A plain `Key Vault Secrets User` grant only carries data-plane access, so Marcus does not qualify for any of the three.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey G",
      },
      {
        id: "G11",
        title: "The role reference needs no auth at all",
        surface: "cli",
        gate: "none",
        command: `rocketvault vault-access roles`,
        expected: "All 11 roles, plus the deprecated legacy names.",
        assert: "Runs with no session; lists 11 roles",
      },
    ],
  },
  {
    key: "H",
    title: "Emergency lockout via explicit deny",
    actor: "Priya — admin. Wren cannot do this.",
    premise:
      "Suspend one operation on one resource for one principal, without touching their role assignment, and revert it instantly. The two 403 strings are the whole point.",
    cases: [
      {
        id: "H1",
        title: "Baseline: Marcus can read the secret",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' $BASE/vaults/prod/secrets/<secret-id> \\
  -H "Authorization: Bearer $MARCUS_TOKEN"`,
        expected: "200",
        assert: "200 before the deny is written",
      },
      {
        id: "H2",
        title: "Write an explicit deny — HTTP only, no CLI command",
        surface: "http",
        gate: "global-admin",
        command: `POLICY_ID=$(curl -s -X POST $BASE/access-policies \\
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \\
  -d '{"principal_id":"<marcus-user-id>","principal_type":"user",
       "resource_type":"secrets","operation":"get","effect":"deny",
       "vault_id":"<prod-vault-id>"}' | jq -r .id)`,
        expected: "A policy id.",
        assert: "Created — there is no CLI equivalent for this",
        flag: "gap",
        after:
          "The deny policy stays active until it is explicitly deleted (H6). Stopping the run anywhere before H6 leaves Marcus locked out of this one secret in `prod`.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey H",
      },
      {
        id: "H3",
        title: "The denial carries a different string from a role denial",
        surface: "http",
        gate: "explicit-deny",
        command: `curl -s $BASE/vaults/prod/secrets/<secret-id> \\
  -H "Authorization: Bearer $MARCUS_TOKEN"`,
        expected: "403 Forbidden: access policy denied",
        assert: "“access policy denied”, not “no role assignment grants…”",
        flag: "divergence",
        notes:
          "Matching only on the status code cannot distinguish this from a Gate 3 denial, and the difference is what tells you whether the deny actually took effect.",
        why: "The explicit-deny check (Gate 2) runs before the per-vault role-assignment check (Gate 3) — a deny here rejects the request before the role check ever runs, which is why the message reads `access policy denied` rather than `no role assignment grants this operation in this vault`. The same ordering means an access-policy deny overrides a role grant the principal genuinely holds.",
        verify: {
          look: "The message reads exactly `access policy denied`, not `no role assignment grants this operation in this vault` (the Gate 3 wording). A 403 with the Gate 3 string means the deny did not take effect and the request fell through to the role check instead — the status code alone cannot tell the two apart.",
        },
        related: [{ id: "H1", rel: "depends" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey H",
      },
      {
        id: "H4",
        title: "The policy is visible per principal",
        surface: "http",
        gate: "global-admin",
        command: `curl -s $BASE/access-policies/principal/<marcus-user-id> \\
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.total'`,
        expected: "1",
        assert: "Exactly 1",
      },
      {
        id: "H5",
        title: "His role assignment is untouched",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access list --vault prod`,
        expected:
          "The Secrets User assignment is still there, unchanged. Marcus appears by principal id, not by name.",
        assert: "The deny is an overlay, not a revocation",
        why: "The explicit-deny check (Gate 2) and the per-vault role check (Gate 3) are separate gates evaluated in sequence. Writing a deny policy only affects Gate 2; it never modifies the role grant Gate 3 reads, so Marcus's Secrets User assignment is unchanged.",
        related: [{ id: "H2", rel: "depends" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey H",
      },
      {
        id: "H6",
        title: "Deleting the policy restores access instantly",
        surface: "http",
        gate: "global-admin",
        command: `curl -s -X DELETE $BASE/access-policies/$POLICY_ID -H "Authorization: Bearer $ADMIN_TOKEN"
curl -s -o /dev/null -w '%{http_code}\\n' $BASE/vaults/prod/secrets/<secret-id> \\
  -H "Authorization: Bearer $MARCUS_TOKEN"`,
        expected: "200",
        assert: "200 again — no restart, no cache flush",
        why: "Access returns on the very next request, with no restart and no cache flush, because the deleted policy row is no longer there to be found when the request is evaluated.",
        related: [{ id: "H2", rel: "depends" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey H (lines 592-596)",
      },
    ],
  },
  {
    key: "I",
    title: "Revoking a compromised service account",
    actor: "Wren",
    premise:
      "The assertion worth running is not “revoke works”. It is that the *same token, with byte-identical claims*, goes from 200 to 403 with no reissue — proving there is no JWT-embedded permission and no revocation lag.",
    cases: [
      {
        id: "I1",
        title: "Capture the assignment id before revoking",
        surface: "cli",
        gate: "management",
        command: `ASSIGNMENT_ID=$(rocketvault vault-access list --vault prod \\
  | awk -v p="$SVC_CLIENT_ID" '$3 == p { print $1 }')`,
        expected: "A UUID.",
        assert: "The id is required — revoke takes no principal name",
        flag: "trap",
        notes:
          "`vault-access list` has no JSON output, so match on the PRINCIPAL-ID column rather than piping to `jq`.",
      },
      {
        id: "I2",
        title: "Prove the token works, and record its claims",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' $BASE/vaults/prod/keys/<key-id> \\
  -H "Authorization: Bearer $SVC_TOKEN"

echo "$SVC_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{exp,jti,sub}'`,
        expected: "200, then the decoded claims. Keep the claims.",
        assert: "200 and a recorded {exp, jti, sub}",
      },
      {
        id: "I3",
        title: "Revoke the assignment",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access revoke "$ASSIGNMENT_ID" --vault prod`,
        expected: "revoked assignment <id>",
        assert: "Revoked",
      },
      {
        id: "I4",
        title: "The same token, no new login, is now denied",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' $BASE/vaults/prod/keys/<key-id> \\
  -H "Authorization: Bearer $SVC_TOKEN"`,
        expected: "403",
        assert: "200 → 403 with no reissue",
        why: "Authorization runs as a live per-request lookup against the `role_assignments` table — there is no cache and no JWT-embedded permission. The token itself is unchanged; only the assignment row is gone, so the very next request after the revoke is denied with no new login and no reissue needed.",
        related: [{ id: "I3", rel: "depends" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey I",
      },
      {
        id: "I5",
        title: "The claims are byte-identical",
        surface: "http",
        gate: "none",
        command: `echo "$SVC_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{exp,jti,sub}'`,
        expected: "Identical to I2 — exp still roughly 55 minutes out.",
        assert: "Nothing about the token changed; only the DB row did",
        why: "Both `PolicyMiddleware` (HTTP) and `RequireDataAction` (CLI) call the same live `HasDataAction` lookup on every request — no cache, no JWT-embedded claim, no revocation lag. The token itself never changes; only the underlying `role_assignments` row does, which is why the decoded claims here are byte-identical to I2.",
        verify: {
          look: "`sub` and `jti` must match I2 character for character — no new token was issued. `exp` matches too; 'roughly 55 minutes out' describes the gap from now, not license to see a different absolute value than I2 recorded.",
        },
        related: [{ id: "I2", rel: "depends" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey I",
      },
      {
        id: "I6",
        title: "Rotate the key the leaked credentials could reach",
        surface: "cli",
        gate: "global-role",
        precondition: "Run as sofia, who holds crypto_manager.",
        command: `rocketvault keys rotate <key-id> --vault prod`,
        expected: "A new key version.",
        assert: "Rotation succeeds; old versions still verify (see C12)",
        why: "Rotating creates a new key version so any material the leaked credentials could reach through the old version is invalidated going forward. Whether the old version still verifies existing signatures is established at C12, not here.",
        related: [{ id: "C12", rel: "depends" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey I",
      },
    ],
  },
  {
    key: "J",
    title: "Retiring a vault, and the purge trap",
    actor: "Priya, then ops-oncall",
    premise:
      "Soft-delete cascades. Recovery cascades, but only for children stamped with the vault's exact `deleted_at`. Purge does not cascade at all, and permanently orphans everything inside.",
    context: [
      "Three operations, three different cascade behaviours. Soft-delete cascades to everything in the vault. Recovery cascades too, but only to children stamped with the vault's exact `deleted_at`. Purge does not cascade at all.",
      "The last of those is the trap this journey exists for, and it is silent — nothing errors and nothing warns. The API cannot show you the rows that are left behind, which is why J6 goes to the database directly.",
    ],
    cases: [
      {
        id: "J1",
        title: "Soft-delete cascades to contained items",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults delete staging`,
        expected:
          "Contained secrets, keys and certs are each stamped with the vault's own deleted_at.",
        assert: "Children are soft-deleted with the vault's timestamp",
        why: "The cascade stamps every contained secret, key and certificate with the vault's own `deleted_at`, not with a timestamp of its own. That shared value is what makes J3's recovery possible, and it is the same fact that excludes J4's earlier-deleted secret from the cascade.",
        verify: {
          look: "Every item the cascade touched carries the same `deleted_at` as the vault row itself, not the time each one was created or last changed. Read that column the way J6 does, straight from the database: no CLI command shows a secret's `deleted_at` — `secrets list` excludes soft-deleted rows and registers only `--tags` — and the one HTTP listing that returns the column, `GET /api/v1/vaults/{vault_name}/deleted/secrets`, 404s for as long as the vault is soft-deleted, which is the whole window this check runs in.",
        },
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J; cmd/secrets/list.go:50,217; api/soft_delete.go:41-48,405; internal/middleware/middleware.go:635-640; internal/repositories/vault_repository.go:134",
      },
      {
        id: "J2",
        title: "Deleted vaults are listable",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults list --include-deleted --output json`,
        expected: "staging appears with a deleted_at.",
        assert: "--include-deleted surfaces it",
        related: [{ id: "J1", rel: "depends" }],
      },
      {
        id: "J3",
        title: "Recovery cascades to matching children only",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults recover staging`,
        expected:
          "Only children whose deleted_at matches the vault's are restored.",
        assert: "Vault and matching children are back",
        why: "Recovery cascades, but the restore is scoped by `WHERE vault_id = ? AND deleted_at = ?`. Only children carrying the vault's exact deletion timestamp come back — which is every item the J1 cascade stamped, and nothing else.",
        related: [{ id: "J1", rel: "depends" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J",
      },
      {
        id: "J4",
        title: "An individually-deleted secret is NOT restored",
        surface: "cli",
        gate: "none",
        precondition:
          "Soft-delete one secret on its own, then delete and recover the whole vault.",
        command: `rocketvault secrets list --vault staging --output json | jq 'length'`,
        expected:
          "The earlier-deleted secret is missing. It carries a different deleted_at and is excluded by the WHERE vault_id = ? AND deleted_at = ? clause.",
        assert: "It needs its own explicit restore",
        flag: "trap",
        notes:
          "Do not assume vault recovery brings everything back. This is the most commonly missed assertion in the whole document.",
        why: "A secret soft-deleted individually, earlier, carries its own `deleted_at`, and that value does not equal the vault's. The `WHERE vault_id = ? AND deleted_at = ?` clause driving the cascade therefore never matches it, so vault recovery steps straight past it.",
        after:
          "The secret is still soft-deleted and still recoverable on its own, but **no CLI command restores it**: the `secrets` group registers only create, get, list, update, delete, generate-password, import and export, and `backup restore` replaces the whole database rather than one row. The only restore path is REST — `POST /api/v1/vaults/staging/deleted/secrets/<secret-id>/restore`, with the ids from `GET /api/v1/vaults/staging/deleted/secrets`. Both resolve the vault by name, so they work here only because J3 already recovered `staging`. The restore route needs `Microsoft.KeyVault/vaults/secrets/recover/action` in `staging` (Key Vault Administrator or Key Vault Secrets Officer), and data-plane routes have no admin short-circuit, so a global admin holding no grant in the vault gets a 403.",
        related: [{ id: "J3", rel: "depends" }],
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J; cmd/secrets/create.go:195, delete.go:151, get.go:180, list.go:215, update.go:184, generate.go:97, import.go:255, export.go:281 (no restore subcommand registered); cmd/backup.go:176; api/soft_delete.go:405-406; internal/services/authorization/data_actions.go:302-305; model/azure_roles.go:27,158,180; internal/services/authorization/data_action_authz.go:12-19",
      },
      {
        id: "J5",
        title: "Separation of duties: a different principal purges",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant ops-oncall --role "Key Vault Purge Operator" --vault staging

rocketvault vaults delete staging
rocketvault vaults purge staging      # as ops-oncall`,
        expected: "The vault row is permanently removed.",
        assert: "Purge Operator can purge",
        notes:
          "`ActionVaultPurge` is granted by **no other role** — not Administrator's data-plane bundle, not Crypto Officer.",
        why: "Purge is deliberately a second pair of hands. The CLI path also carries an admin bypass in `CanPurgeVault` that the HTTP route does not have, so a global admin succeeds here and takes a 403 for the same purge over REST.",
        related: [{ id: "K3", rel: "diverges" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey K",
      },
      {
        id: "J6",
        title: "Purge orphans the vault's contents permanently",
        surface: "db",
        gate: "none",
        command: `sqlite3 /tmp/rv-test.db \\
  "SELECT id, name, vault_id, deleted_at FROM secrets WHERE vault_id='<purged-vault-id>';"`,
        expected:
          "Rows still present, still soft-deleted, pointing at a vault that no longer exists.",
        assert: "Orphaned rows survive the purge",
        flag: "trap",
        notes:
          "**Purge a vault's contents item-by-item before purging the vault**, or accept permanently orphaned rows.",
        why: "`PurgeVault` deletes the vault row and its `access_policies` rows and stops. There is no cascade call, and no foreign key forcing one — `secrets`, `keys` and `certificates` carry a plain `vault_id TEXT NOT NULL` with no `REFERENCES vaults(id)`, unlike `role_assignments.vault_id`, which does have `ON DELETE CASCADE`.",
        verify: {
          look: "Rows come back. They are still soft-deleted, and their `vault_id` names a vault that is no longer in the `vaults` table. **Rows coming back is the pass here, not the failure** — an empty result means the orphaning did not happen and something about this build differs from the document.",
        },
        after:
          "Nothing to undo; the rows cannot be reached to be undone. Vault-scoped routes 404 because the name no longer resolves, flat routes only ever reach `default`, and the purge scheduler never sweeps them because it purges individually-deleted items only.",
        related: [{ id: "J5", rel: "depends" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J — the purge trap",
      },
      {
        id: "J7",
        title: "Purge-protected contents block a bulk purge",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults purge <vault-with-protected-contents>`,
        expected: "Error: ... purge protection enabled",
        assert: "Fail-closed — the one guardrail that does exist",
        why: "The one guardrail that does exist in the other direction, and it fails closed: a vault holding any purge-protected item refuses the bulk purge.",
        related: [{ id: "J5", rel: "contrasts" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J",
      },
    ],
  },
  {
    key: "K",
    title: "The CLI/HTTP purge divergence",
    actor: "Priya, admin, with no Purge Operator grant in dev",
    premise:
      "Same person, same authority, same vault — two different answers depending on which door she walks through. Confirm it explicitly rather than assuming parity.",
    cases: [
      {
        id: "K1",
        title: "Soft-delete dev first",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults delete dev`,
        expected: "Soft-deleted.",
        assert: "Purge requires a prior delete",
      },
      {
        id: "K2",
        title: "HTTP purge has no admin bypass",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' -X DELETE $BASE/vaults/dev/purge \\
  -H "Authorization: Bearer $ADMIN_TOKEN"`,
        expected: "403",
        assert: "403 for a global admin with no Purge Operator grant",
        why: "The HTTP purge route has no admin short-circuit: a global admin holding no `Key Vault Purge Operator` grant in `dev` fails the same role check anyone else without the role would fail.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey K",
      },
      {
        id: "K3",
        title: "CLI purge does have an admin bypass",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults purge dev`,
        expected: "Succeeds.",
        assert: "Succeeds for the same principal that got 403 in K2",
        flag: "divergence",
        notes: "Both are intentional; they simply disagree.",
        why: "`CanPurgeVault` short-circuits for the global admin role, so Priya's `admin` account passes the CLI check without ever needing a `Key Vault Purge Operator` grant — unlike the HTTP route (K2), which has no such short-circuit.",
        verify: {
          command: "rocketvault vaults list --include-deleted --output json",
          look: "`dev` is gone from the list entirely, not merely shown as soft-deleted — a purge removes the vault row outright. If it is still listed with a `deleted_at`, the purge did not actually run.",
        },
        after:
          "Like any vault purge, this permanently removes the vault row without cascading to its contents. Anything still inside `dev` becomes an orphaned, unreachable row exactly as described for the purge trap — purge its contents first if it holds anything.",
        related: [{ id: "J5", rel: "diverges" }],
        source:
          "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey K; VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey J — the purge trap",
      },
      {
        id: "K4",
        title: "A non-admin Purge Operator succeeds on both doors",
        surface: "both",
        gate: "vault-role",
        command: `# CLI:  rocketvault vaults purge dev
# HTTP: curl -X DELETE $BASE/vaults/dev/purge -H "Authorization: Bearer $OPS_TOKEN"`,
        expected: "Both succeed.",
        assert: "The divergence affects admins only",
        why: "Both doors ultimately gate on the same `Key Vault Purge Operator` grant for a non-admin caller — there is no admin short-circuit to diverge from when the caller already holds the role the check is looking for. The CLI/HTTP split in K2 and K3 only appears for an admin who lacks that grant.",
        related: [{ id: "K3", rel: "contrasts" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey K",
      },
    ],
  },
  {
    key: "L",
    title: "Compliance auditor",
    actor: "Dae-Ho — global role user, Key Vault Reader",
    premise:
      "Read-only across two vaults. The friction point: a vault-scoped read-only auditor cannot self-serve audit evidence, because audit logs are admin-only and cut across every vault.",
    cases: [
      {
        id: "L1",
        title: "Grant Reader in two vaults",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant daeho --role "Key Vault Reader" --vault prod
rocketvault vault-access grant daeho --role "Key Vault Reader" --vault staging`,
        expected: "Two assignments.",
        assert: "Both granted",
      },
      {
        id: "L2",
        title: "keys list and get need no global role",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault keys list --vault prod --output json`,
        expected:
          "The key list, despite daeho holding only global role `user`.",
        assert: "Works — read commands skip Correction 8's gate",
        notes:
          "Compare with C1, where the same user's `keys create` would be refused by the global-role gate before the vault check ran.",
        why: "Correction 8's global-role gate applies only to mutating key commands (`create/update/delete/rotate/sign/verify/wrap/unwrap`, plus `rotation-policy set/delete`). `keys get`/`keys list`/`rotation-policy get` are the row in that table with no global-role requirement at all — only the vault data action is checked.",
        related: [
          { id: "L1", rel: "depends" },
          { id: "C1", rel: "contrasts" },
        ],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Correction 8",
      },
      {
        id: "L3",
        title: "Secret metadata is visible; values are not",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault secrets list --vault prod --output json
rocketvault secrets get <secret-id> --vault prod`,
        expected:
          "The list renders. The get fails: forbidden — Reader holds readMetadata, not secrets/get",
        assert: "List works, get is denied",
      },
      {
        id: "L4",
        title: "Certificates are readable under Reader",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault certificate get <cert-id> --vault prod`,
        expected: "The certificate record.",
        assert: "Cert reads need no certificate_manager",
      },
      {
        id: "L5",
        title: "Audit logs are admin-only — the Reader grants are irrelevant",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault audit logs --limit 50`,
        expected: "Error: forbidden",
        assert: "Denied despite holding Reader in both vaults",
        flag: "gap",
        notes:
          "Worth flagging to whoever designs your compliance process: the auditor has to ask an admin for their own evidence.",
        why: "Audit logs are gated by a global admin check, not by any vault-scoped role assignment. Reader is a per-vault grant and audit cuts across every vault, so holding it in `prod` and `staging` has no bearing on this gate at all.",
        related: [{ id: "L1", rel: "contrasts" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey L",
      },
      {
        id: "L6",
        title: "The same denial over HTTP",
        surface: "http",
        gate: "global-admin",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' $BASE/audit/logs \\
  -H "Authorization: Bearer $DAEHO_TOKEN"`,
        expected: "403",
        assert: "403",
      },
      {
        id: "L7",
        title: "An admin runs the query on his behalf",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault audit logs --from 2026-07-01 --to 2026-09-30 \\
  --action create_key --outcome success --limit 100 --output json`,
        expected: "Matching entries.",
        assert: "Filters by date, action and outcome",
        related: [{ id: "L5", rel: "contrasts" }],
      },
      {
        id: "L8",
        title: "Compliance reports",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault audit report --type soc2 --from 2026-07-01 --to 2026-09-30 --format csv
rocketvault audit report --type gdpr --from 2026-07-01 --to 2026-09-30 \\
  --subject-id <daeho-user-id>`,
        expected: "A SOC2 CSV, and a GDPR report scoped to one subject.",
        assert: "Both report types render",
      },
      {
        id: "L9",
        title: "audit config views when no retention value is passed",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault audit config`,
        expected: "Current audit log retention: 90 days",
        assert: "Reads, does not write",
        flag: "trap",
        notes: "The same command with a value writes.",
        why: "`audit config` treats an omitted or explicit `0` value for `--retention-days` as a read: the command only prints the current retention rather than writing anything.",
        related: [{ id: "L10", rel: "contrasts" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey L",
      },
      {
        id: "L10",
        title: "audit config sets when a value is passed",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault audit config --retention-days 90`,
        expected: "Retention policy updated: 90 days",
        assert: "Writes; a daily job then purges older entries",
      },
      {
        id: "L11",
        title: "Tear down the temporary grant",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access revoke <daeho-staging-assignment-id> --vault staging`,
        expected: "Revoked.",
        assert: "staging access ends; prod access remains",
      },
    ],
  },
  {
    key: "M",
    title: "Offboarding",
    actor: "Priya and Wren",
    premise:
      "There is no “revoke everything” command. The steps that are easy to forget are the per-vault enumeration and the explicit-deny policies, which user deletion does not remove.",
    cases: [
      {
        id: "M1",
        title: "Enumerate assignments per vault",
        surface: "cli",
        gate: "management",
        command: `for V in default dev staging prod; do
  echo "== $V"
  rocketvault vault-access list --vault "$V" \\
    | awk -v p="$MARCUS_ID" '$3 == p { print $1, $2 }'
done`,
        expected: "Every assignment across every vault.",
        assert: "You must loop — there is no cross-vault listing",
        flag: "gap",
        why: "Every `vault-access` command in the document takes a single `--vault` — there is no command that lists or revokes role assignments across every vault at once, so removing a principal's access instance-wide means enumerating each vault yourself, as this loop does.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey M",
      },
      {
        id: "M2",
        title: "Revoke each assignment",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access revoke <assignment-id> --vault dev`,
        expected: "Takes effect on his very next request.",
        assert: "Revoked, one call per assignment",
        after:
          "Only the `dev` assignment shown here is revoked. Repeat this call for every assignment M1 found, in every vault it appeared in, or the offboarding is incomplete.",
        related: [{ id: "M1", rel: "depends" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey M",
      },
      {
        id: "M3",
        title: "Deleting the account 401s the existing JWT immediately",
        surface: "both",
        gate: "global-admin",
        command: `rocketvault users delete <marcus-user-id>

curl -s -o /dev/null -w '%{http_code}\\n' $BASE/vaults/dev/secrets \\
  -H "Authorization: Bearer $MARCUS_TOKEN"`,
        expected: "401",
        assert: "401, not 403, and not at TTL expiry",
        notes:
          "Contrast with I4, where a revoked *role* gives 403 and the token stays valid.",
        why: "Revoking a role assignment (I4) leaves the account able to authenticate — the token still passes signature and expiry checks, so the request reaches the authorization check and fails there with 403. Deleting the user removes the account authentication depends on entirely, so the same token fails to authenticate at all and returns 401 instead.",
        related: [{ id: "I4", rel: "contrasts" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey M (lines 790-796)",
      },
      {
        id: "M4",
        title: "Explicit-deny policies survive user deletion",
        surface: "http",
        gate: "global-admin",
        command: `curl -s $BASE/access-policies/principal/<marcus-user-id> \\
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.policies[].id' \\
  | xargs -I{} curl -s -X DELETE $BASE/access-policies/{} \\
      -H "Authorization: Bearer $ADMIN_TOKEN"`,
        expected:
          "The policies were still there after the user was deleted, and are now removed.",
        assert: "Policies named him even after deletion",
        flag: "trap",
        notes:
          "Left behind, these accumulate as dangling denies against ids that no longer resolve. Clean them up as part of offboarding.",
        why: "User deletion does not remove `access_policies` rows naming that user — the document is explicit that this step does not happen automatically. A deny written against Marcus's user id keeps existing, now naming an id that resolves to nobody, until an admin deletes it by hand.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey M",
      },
      {
        id: "M5",
        title: "Clear the cached CLI session on shared machines",
        surface: "local",
        gate: "none",
        command: `rocketvault users logout`,
        expected: "The session file is deleted.",
        assert: "Client-side only — the JWT is not revoked server-side",
        why: "`users logout` deletes only the locally cached session file under `~/.rocketvault/sessions/` — the same cache the setup section describes as something HTTP never reads. Removing it does not call anything server-side, so the JWT itself stays valid, on any machine that already holds a copy, until its own expiry.",
        related: [{ id: "M3", rel: "contrasts" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey M (lines 804-806)",
      },
    ],
  },
]
