import type { Suite } from "./types"

export const journeysVW: Suite[] = [
  {
    key: "V",
    title: "Delegating vault creation without delegating the instance",
    actor:
      "Priya — admin, issuing the grant; Wren — global role user, the provisioning grantee",
    premise:
      "A provisioning grant is the bounded alternative to a global vaults:manage policy: it buys the right to create vaults up to a fixed quota, and nothing else — no authority over a vault it did not create, and, the point of the whole journey, no way to delegate managing the grant itself.",
    cases: [
      {
        id: "V1",
        title:
          "Issuing a grant prints the resolved principal UUID, not the typed name",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault vault-provisioning grant wren --quota 3`,
        expected: `Provisioning grant issued: principal=4f2c8a10-6f1b-4a53-9c2e-0d7b8e5a1c34 quota=3`,
        assert: "Success line shows the resolved UUID, never the literal wren",
        flag: "trap",
        notes:
          "`resolvePrincipal` parses the argument as a UUID first and falls back to a username lookup, and what prints is the stored grant's `principal_id`. A QA case asserting the literal string `wren` in this output fails on a correct build.",
      },
      {
        id: "V2",
        title: "A raw UUID is accepted directly, ahead of any username lookup",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault vault-provisioning grant 3b1e6c2a-9e4b-4f2d-8a2f-6b1c9d0e7f5a --quota 20`,
        expected: `Provisioning grant issued: principal=3b1e6c2a-9e4b-4f2d-8a2f-6b1c9d0e7f5a quota=20`,
        assert: "UUID form succeeds with no username to resolve",
        notes:
          "An OAuth2 service account is an `oauth2_clients` row with no username to look up, so the grant path must accept a bare UUID directly.",
      },
      {
        id: "V3",
        title:
          "Re-issuing a grant for the same principal updates the quota, it does not stack",
        surface: "cli",
        gate: "global-admin",
        precondition: "wren already holds the grant issued in V1.",
        command: `rocketvault vault-provisioning grant wren --quota 10`,
        expected: `Provisioning grant issued: principal=4f2c8a10-6f1b-4a53-9c2e-0d7b8e5a1c34 quota=10`,
        assert: "Same principal, quota now 10 — not a second grant row",
        notes:
          "`principal_id` is `UNIQUE` and the repository upsert updates only the quota, leaving `id`, `created_by` and `created_at` as they were.",
      },
      {
        id: "V4",
        title: "A zero or negative quota is refused, with the reason stated",
        surface: "cli",
        gate: "validation",
        command: `rocketvault vault-provisioning grant wren --quota 0
rocketvault vault-provisioning grant wren --quota -1`,
        expected: `Error: --quota must be a positive integer: a zero-quota grant is indistinguishable from no grant
Error: --quota must be a positive integer: a zero-quota grant is indistinguishable from no grant`,
        assert: "Same validation error for zero and for negative",
      },
      {
        id: "V5",
        title:
          "Omitting --quota entirely gives the same error, not cobra's required-flag message",
        surface: "cli",
        gate: "validation",
        command: `rocketvault vault-provisioning grant wren`,
        expected: `Error: --quota must be a positive integer: a zero-quota grant is indistinguishable from no grant`,
        assert:
          "No cobra required-flag error — --quota is a plain Int flag defaulting to 0",
        flag: "trap",
        notes:
          '`--quota` is documented as required but is **not** registered with cobra\'s required-flag machinery, so omitting it entirely produces the ordinary positive-integer error, not `required flag(s) "quota" not set`. Note also the check ordering: the admin check runs before this one, so a non-admin who types a bad quota sees the permission error, never this one.',
      },
      {
        id: "V6",
        title:
          "Data Access Administrator buys nothing here — grant, revoke and list all refuse",
        surface: "cli",
        gate: "global-admin",
        precondition:
          "Run as wren, holding Key Vault Data Access Administrator in prod.",
        command: `rocketvault vault-provisioning grant marcus --quota 5
rocketvault vault-provisioning revoke marcus
rocketvault vault-provisioning list`,
        expected: `Error: permission denied: managing vault provisioning grants requires the admin role
Error: permission denied: managing vault provisioning grants requires the admin role
Error: permission denied: managing vault provisioning grants requires the admin role`,
        assert:
          "Denied on all three — the one CLI tier with no delegation path at all",
        flag: "trap",
        notes:
          "`requireGrantAdmin` reads the caller's account roles and checks one thing: `common.HasAnyRole(roles, model.RoleAdmin)` — no access-policy path, no role-assignment path. The code states its own reason: 'a principal able to amend grants could raise its own quota, and the bound the grant exists to impose would be decorative.' A provisioning grant confers nothing over provisioning grants, even to its own holder.",
      },
      {
        id: "V7",
        title: "list is instance-wide; --vault parses but is silently ignored",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault vault-provisioning list

rocketvault vault-provisioning list --vault prod`,
        expected: `PRINCIPAL-ID                           QUOTA    CREATED-AT
4f2c8a10-6f1b-4a53-9c2e-0d7b8e5a1c34   10       2026-09-05T11:04:22Z
3b1e6c2a-9e4b-4f2d-8a2f-6b1c9d0e7f5a   20       2026-09-05T11:07:51Z

identical output with --vault prod — same rows, no filtering`,
        assert: "Every grant on the instance, and --vault changes nothing",
        flag: "trap",
        notes:
          "A grant is a global right to create vaults, not a right inside one, so this lists every grant on the instance. `--vault` is a root-level persistent flag, so it parses here and is then ignored — `runList` never reads it.",
      },
      {
        id: "V8",
        title:
          "--output json is ignored too — runList never reaches the formatter",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault vault-provisioning list --output json`,
        expected: "The same table as a plain list call. No JSON anywhere.",
        assert: "--output json is silently ignored — table printed anyway",
        flag: "trap",
        notes:
          "`runList` writes with `fmt.Fprintf` and never reaches the output formatter, so the flag parses and does nothing. This is the opposite of `vaults list`, which does honour `--output` — so a script that pipes one into `jq` and the other into `jq` breaks on only one of them.",
      },
      {
        id: "V9",
        title: "The header row prints even when there are zero grants",
        surface: "cli",
        gate: "global-admin",
        precondition: "A fresh instance, no provisioning grants issued yet.",
        command: `rocketvault vault-provisioning list`,
        expected: `PRINCIPAL-ID                           QUOTA    CREATED-AT`,
        assert:
          "Header only — not a 'no grants' message, it prints unconditionally",
        flag: "trap",
      },
      {
        id: "V10",
        title: "Three creates succeed under a quota of 3",
        surface: "cli",
        gate: "management",
        precondition: "Run as wren, holding the quota-3 grant issued in V1.",
        command: `rocketvault vaults create tenant-a
rocketvault vaults create tenant-b
rocketvault vaults create tenant-c`,
        expected:
          "each prints the create table: ID  Name  Enabled  PurgeProtection  RetentionDays  Created",
        assert: "All three succeed under the quota of 3",
      },
      {
        id: "V11",
        title:
          "The fourth create fails: quota exceeded, and soft-deleting does not free a slot",
        surface: "cli",
        gate: "management",
        precondition:
          "wren has already created tenant-a, tenant-b and tenant-c (V10), using all of quota 3.",
        command: `rocketvault vaults create tenant-d`,
        expected: `Error: failed to create vault: vault provisioning quota exceeded: 3 of 3 used -- soft-deleting
a vault does not free a quota slot; a slot is released only when the vault is purged, which
requires an administrator or a Key Vault Purge Operator grant. Ask an administrator to purge a
vault or raise your quota`,
        assert:
          "Refused at 3 of 3 — soft-deleting a vault does not free the slot",
        flag: "trap",
        notes:
          "The quota check runs inside the insert transaction, so two concurrent creates cannot both pass a check-then-insert race.",
      },
      {
        id: "V12",
        title: "A quota-bounded create may not set --purge-protection",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults create tenant-e --purge-protection`,
        expected: `Error: failed to create vault: purge protection may only be set on a create that is not
quota-bounded -- a quota-bounded provisioning grant cannot set --purge-protection; an admin
or a global vaults:manage holder can`,
        assert:
          "Refused — purge protection is closed to a quota-bounded create",
        flag: "trap",
        notes:
          "Deliberate: a grantee who could set purge protection would soft-delete a protected vault and hold its slot forever. Wren cannot free her own slot either way — purge is gated on CanPurgeVault, and the creator grant she receives, Key Vault Administrator, does not carry ActionVaultPurge (Journey J).",
      },
      {
        id: "V13",
        title: "She manages what she created: delete succeeds",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults delete tenant-a`,
        expected: "succeeds — she manages what she created",
        assert: "Delete succeeds on her own creation",
      },
      {
        id: "V14",
        title: "But she cannot free the slot: purge is refused",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults purge tenant-a`,
        expected:
          'Error: permission denied: admin or Key Vault Purge Operator required for vault "tenant-a"',
        assert:
          "Purge denied — Key Vault Administrator does not carry ActionVaultPurge",
        flag: "trap",
      },
      {
        id: "V15",
        title: "She has no authority at all over a vault she did not create",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults get prod`,
        expected:
          'Error: permission denied: admin or vaults/manage required for vault "prod"',
        assert: "Denied on prod — created by Priya, not her",
      },
      {
        id: "V16",
        title: "Revoking a grant prints the resolved UUID too",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault vault-provisioning revoke wren`,
        expected: `Provisioning grant revoked: principal=4f2c8a10-6f1b-4a53-9c2e-0d7b8e5a1c34`,
        assert: "Revoked — again the UUID, not the typed wren",
        flag: "trap",
        notes:
          "Same `resolvePrincipal` path as grant, and the same trap for a test asserting the typed argument.",
      },
      {
        id: "V17",
        title: "After revocation, she can no longer create",
        surface: "cli",
        gate: "management",
        precondition: "wren's provisioning grant was just revoked (V16).",
        command: `rocketvault vaults create tenant-f`,
        expected: `Error: permission denied: admin, a global vaults/manage grant, or a vault provisioning grant
required to create a vault`,
        assert: "Create refused immediately after revoke",
      },
      {
        id: "V18",
        title: "Revocation does not cascade: an existing vault stays reachable",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults get tenant-b`,
        expected: "still succeeds",
        assert: "get still works on a vault created before the revoke",
        flag: "trap",
        notes:
          "`vault-provisioning revoke`'s help states it outright: it leaves every vault the principal already created, and that vault's own access grants, untouched. Removing access to existing vaults is a separate operator action.",
      },
      {
        id: "V19",
        title: "Revocation does not cascade: data-plane access survives too",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault secrets list --vault tenant-b`,
        expected: "still succeeds — Key Vault Administrator survives",
        assert:
          "Data-plane access unaffected — revoking a grant is not offboarding",
        flag: "trap",
        notes:
          "Offboarding means revoking the grant **and** removing the per-vault creator grants — the vault-scoped `vaults:manage` policy (HTTP only, Journey W) and the `Key Vault Administrator` role assignment (`vault-access revoke <assignment-id> --vault tenant-b`) — for every vault the principal created.",
      },
      {
        id: "V20",
        title: "Both grant and revoke are logged with a named actor",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault audit logs --action issue_provisioning_grant --limit 20 --output json
rocketvault audit logs --action revoke_provisioning_grant --limit 20 --output json`,
        expected:
          "Entries for both actions, each carrying priya as a named actor.",
        assert: "Actor is always named, never anonymous",
        notes:
          "The actor comes from `requireGrantAdmin`'s return value — the CLI has no middleware to stamp one for it. " +
          "A create made under a grant is distinguishable from every other create in the same log: `Vault created under provisioning grant: <name>`, versus plain `Vault created: <name>` for an admin and `Vault created under global vaults:manage grant (creator rights granted): <name>` for Journey W's Iris.",
      },
    ],
  },
  {
    key: "W",
    title: "The global grant that no longer means what it used to",
    actor: "Iris — global role user, plus a global vaults:manage access policy",
    premise:
      "As of v4.6.0 a global (vault_id NULL) (vaults, manage, allow) policy confers create and list only. Its holder keeps full control over a vault it created, because creation writes it a scoped policy and role assignment of its own, but loses everything else on a vault it did not create.",
    cases: [
      {
        id: "W1",
        title:
          "Omitting vault_id on the access-policy POST is what makes it global",
        surface: "http",
        gate: "global-admin",
        precondition: "Run as priya (admin).",
        command: `POLICY_ID=$(curl -s -X POST $BASE/access-policies \\
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \\
  -d '{"principal_id":"<iris-user-id>","principal_type":"user",
       "resource_type":"vaults","operation":"manage","effect":"allow"}' | jq -r .id)

curl -s $BASE/access-policies/$POLICY_ID -H "Authorization: Bearer $ADMIN_TOKEN" | jq .`,
        expected:
          "no vault_id field in the response — VaultID is omitempty and nil means GLOBAL",
        assert: "No vault_id in the response confirms a global policy",
        notes:
          "There is no CLI command for access policies — the only mechanism is the admin-gated `POST /api/v1/access-policies`, gated by `requireAccessPolicyAdmin`. `vault_id` is a STRING in `CreateAccessPolicyRequest`: an empty value leaves the policy global, a value scopes it to that vault.",
      },
      {
        id: "W2",
        title:
          "A vault-access role grant is not a substitute for the HTTP policy",
        surface: "cli",
        gate: "management",
        precondition: "Run as priya (admin).",
        command: `rocketvault vault-access grant iris --role "Key Vault Administrator" --vault prod`,
        expected:
          "granted Key Vault Administrator to iris in vault (assignment <id>)",
        assert:
          "Writes role_assignments only — CanManageVault still sees nothing",
        flag: "gap",
        notes:
          "`ExpandRole` returns `nil, nil` for every Azure built-in role, so this writes `role_assignments` rows and nothing `CanManageVault` can see. It satisfies data-plane checks and nothing else, however much it looks like a substitute.",
      },
      {
        id: "W3",
        title: "Create still works under the global policy",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults create tenant-x`,
        expected: `ID  Name  Enabled  PurgeProtection  RetentionDays  Created`,
        assert:
          "Create succeeds — the collection-level decision still calls CheckAccess",
      },
      {
        id: "W4",
        title: "list shows every vault, including ones she cannot manage",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults list`,
        expected:
          "every vault on the instance — dev, staging, prod, tenant-x, ...",
        assert: "She sees vaults she cannot touch — listing is not managing",
        flag: "trap",
        notes:
          '`vaults list` treats her as an "all" lister, which a NULL-scoped allow satisfies via CheckAccess. That asymmetry is the single most confusing thing about this release in practice, and it is intended.',
      },
      {
        id: "W5",
        title: "Unlike a provisioning grantee, she may set purge protection",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults create tenant-y --purge-protection`,
        expected: "succeeds",
        assert: "Purge protection open to her — she has no quota to protect",
        notes:
          "Three tiers exist on the create path, and only the middle one is refused: admin may set purge protection, a global-policy holder may set it, a provisioning grantee (Journey V) may not.",
      },
      {
        id: "W6",
        title: "She fully manages the vault she created",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults get tenant-x
rocketvault vaults update tenant-x --retention-days 14
rocketvault vault-webhook get --vault tenant-x
rocketvault vault-access list --vault tenant-x`,
        expected: "all succeed",
        assert:
          "get, update, webhook get and vault-access list all succeed on her own vault",
        notes:
          "None of this comes from the global policy. `cmd/vaults/create.go` passes `right != authz.CreateRightAdmin` as `grantCreatorRights`, and `CreateVaultProvisioned` writes, in the same transaction as the vault row, a vault-scoped `vaults:manage` access policy **and** a `Key Vault Administrator` role assignment for the creator.",
      },
      {
        id: "W7",
        title: "The creator policy really is vault-scoped, not global",
        surface: "http",
        gate: "global-admin",
        precondition: "Run as priya (admin).",
        command: `curl -s $BASE/access-policies/principal/<iris-user-id> \\
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.access_policies[] | {operation, effect, vault_id}'`,
        expected:
          "one row with no vault_id (the global allow) plus one row per vault she created, each carrying that vault's UUID",
        assert: "One global row, plus one scoped row per vault she created",
      },
      {
        id: "W8",
        title: "She cannot get, update or delete a vault she did not create",
        surface: "cli",
        gate: "management",
        precondition: "Against prod, which Priya created in Journey A.",
        command: `rocketvault vaults get prod
rocketvault vaults update prod --retention-days 7
rocketvault vaults delete prod`,
        expected: `Error: permission denied: admin or vaults/manage required for vault "prod"
Error: permission denied: admin or vaults/manage required for vault "prod"
Error: permission denied: admin or vaults/manage required for vault "prod"`,
        assert: "Denied on all three — the actual breaking change in v4.6.0",
        flag: "trap",
        notes:
          "A concrete vault ID routes CanManageVault to CheckVaultScopedAccess instead of CheckAccess. That method reuses the same (vault_id = ? OR vault_id IS NULL) lookup, then discards NULL-scoped allow rows and keeps NULL-scoped deny rows — her global allow survives the query and is thrown away by the filter, so the decision falls through to AccessFallback, which is not AccessAllowed.",
      },
      {
        id: "W9",
        title: "Webhook configuration is denied the same way",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-webhook set --vault prod --url https://hooks.example/rocketvault`,
        expected: `Error: permission denied: managing webhook config for vault "prod" requires admin or vaults/manage`,
        assert: "Denied — webhook config is also behind CanManageVault",
      },
      {
        id: "W10",
        title:
          "Role-assignment management is denied too — the escalation this closes",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant iris --role "Key Vault Administrator" --vault prod`,
        expected: `Error: permission denied: admin, vaults/manage, or Key Vault Data Access Administrator
required for this vault`,
        assert:
          "Denied — she cannot self-award Key Vault Administrator in prod",
        notes:
          "This is why CanManageVault and CanManageRoleAssignments were narrowed together: role-assignment management alone would otherwise be enough to self-award Key Vault Administrator anywhere, leaving the escalation wide open.",
      },
      {
        id: "W11",
        title: "A global deny still blocks even the vault she created",
        surface: "cli",
        gate: "explicit-deny",
        precondition:
          'Run as priya (admin), issuing the same POST as W1 but with effect "deny" and no vault_id.',
        command: `rocketvault vaults get tenant-x`,
        expected:
          'Error: permission denied: admin or vaults/manage required for vault "tenant-x"',
        assert: "Denied — the vault she created, now unreachable",
        flag: "trap",
        notes:
          "The asymmetry between deny and allow is deliberate: a global NULL-scoped deny still matches every vault, but a global NULL-scoped allow matches none once a concrete vault ID is in play. The admin account role is untouched by any of this — it short-circuits both functions before any policy check runs.",
      },
      {
        id: "W12",
        title:
          "Help text was corrected to say 'scoped to this vault', not 'or granted globally'",
        surface: "cli",
        gate: "none",
        command: `rocketvault vaults get --help | grep -A1 'access-policy allow'`,
        expected: `Requires the admin account role, or an access-policy allow on (vaults,
manage) scoped to this vault.`,
        assert: "Help no longer promises a global allow will do",
        flag: "trap",
        notes:
          '`cmd/vaults/list.go` still says "granted globally" — correctly, the only one that should. `cmd/vaults/create.go` says the allow must be scoped globally rather than to a specific vault, since the vault being created does not exist yet to scope the check to — the same fact from the other side.',
      },
    ],
  },
]
