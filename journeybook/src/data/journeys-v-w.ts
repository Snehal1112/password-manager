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
          "A QA case asserting the literal string `wren` in this output fails on a correct build.",
        why: "`resolvePrincipal` parses the argument as a UUID first and falls back to a username lookup. The success line prints the stored grant's `principal_id` — what that lookup resolved to — never the argument you typed.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey V, step 1",
      },
      {
        id: "V2",
        title: "A raw UUID is accepted directly, ahead of any username lookup",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault vault-provisioning grant 3b1e6c2a-9e4b-4f2d-8a2f-6b1c9d0e7f5a --quota 20`,
        expected: `Provisioning grant issued: principal=3b1e6c2a-9e4b-4f2d-8a2f-6b1c9d0e7f5a quota=20`,
        assert: "UUID form succeeds with no username to resolve",
        why: "An OAuth2 service account is an `oauth2_clients` row with no username to look up, so `resolvePrincipal` must accept a bare UUID directly, ahead of any username lookup.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey V, step 1",
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
        why: "`principal_id` is `UNIQUE` on the `vault_provisioning_grants` table, and the repository issues an `ON CONFLICT (principal_id) DO UPDATE SET quota` upsert. Re-issuing for the same principal updates only the quota; `id`, `created_by` and `created_at` are untouched.",
        related: [{ id: "V1", rel: "depends" }],
        source:
          "internal/repositories/vault_provisioning_grant_repository.go:44-53",
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
          '`--quota` is documented as required but is **not** registered with cobra’s required-flag machinery, so omitting it entirely produces the ordinary positive-integer error, not `required flag(s) "quota" not set`.',
        why: "`--quota` is a plain `Int` flag defaulting to `0` (`cmd/vault-provisioning/grant.go`), never registered with cobra's required-flag machinery, so an omitted value reaches the same `quota <= 0` check a literal `--quota 0` would. `runGrant` checks admin (`requireGrantAdmin`) before it checks quota, so a non-admin caller who also supplies a bad quota sees the permission error, never this one.",
        source:
          "cmd/vault-provisioning/grant.go:42-47 (admin check first); cmd/vault-provisioning/grant.go:103 (--quota Int flag, no MarkFlagRequired)",
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
          "A provisioning grant confers nothing over provisioning grants, even to its own holder.",
        why: "`requireGrantAdmin` (`cmd/vault-provisioning/authz.go`) checks only `HasAnyRole(roles, model.RoleAdmin)` — no access-policy path, no role-assignment path, unlike every other CLI authorization tier in RocketVault. It is deliberate: a principal able to amend its own provisioning grant could raise its own quota, and the bound the grant exists to impose would be decorative. Key Vault Data Access Administrator — the one role built to delegate access management — buys Wren nothing here.",
        related: [{ id: "G1", rel: "depends" }],
        source: "cmd/vault-provisioning/authz.go:31-46",
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
        notes: "`--vault` parses here and is then ignored.",
        why: "A provisioning grant is a global right to create vaults, not a right scoped to one, so `runList` lists every grant on the instance regardless of vault. `--vault` is a root-level persistent flag, so it still parses, but `runList` (`cmd/vault-provisioning/list.go`) never reads it.",
        verify: {
          look: "Run both commands and diff the output — the two PRINCIPAL-ID/QUOTA/CREATED-AT tables must be identical, not merely similar; `--vault prod` must not drop, reorder, or filter a single row.",
        },
        source: "cmd/vault-provisioning/list.go:18-31",
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
          "A script that pipes this and `vaults list` into `jq` breaks on only one of them.",
        why: "`runList` (`cmd/vault-provisioning/list.go`) writes with `fmt.Fprintf` directly and never calls the output formatter, so `--output json` parses but has nothing to act on. This is the opposite of `vaults list`, which does honour `--output`.",
        verify: {
          look: "The output is the plain PRINCIPAL-ID/QUOTA/CREATED-AT table — no `{`, `[`, or JSON keys anywhere, even though `--output json` was passed.",
        },
        source: "cmd/vault-provisioning/list.go:18-31",
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
        why: "The quota check runs inside the same transaction that inserts the vault row (`CreateVaultProvisioned`), so a check-then-insert race can't let two concurrent creates both pass. Soft-deleting a vault does not touch the quota count — the count query counts every vault the principal created, deleted or not — so the slot stays occupied until the vault is purged.",
        source:
          "internal/services/vaults/vault_service.go:363-417; internal/repositories/vault_repository.go:158-165 (CountByCreatedBy: SELECT COUNT(*) ... WHERE created_by = ?, no deleted_at filter)",
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
          "Wren cannot free her own slot either way — purge is gated on `CanPurgeVault`, and the creator grant she receives, Key Vault Administrator, does not carry `ActionVaultPurge` (Journey J).",
        why: "`CreateVaultProvisioned` refuses purge protection outright whenever `quotaBounded` is true and `PurgeProtection` is set. The reason is closing a trap: a grantee who could set purge protection could soft-delete a protected vault and permanently hold its slot.",
        related: [{ id: "W5", rel: "contrasts" }],
        source: "internal/services/vaults/vault_service.go:372-374",
      },
      {
        id: "V13",
        title: "She manages what she created: delete succeeds",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults delete tenant-a`,
        expected: "succeeds — she manages what she created",
        assert: "Delete succeeds on her own creation",
        why: "She manages tenant-a because `CreateVaultProvisioned` wrote her a vault-scoped `(vaults, manage, allow)` access-policy row for it at creation time, and `vaults delete` checks exactly that policy via `CanManageVault`. It is not her provisioning grant or her Key Vault Administrator role assignment doing the work — a provisioning grant carries no vault-management authority at all.",
        related: [{ id: "V10", rel: "depends" }],
        source:
          "internal/services/vaults/vault_service.go:428-443; cmd/vaults/authz.go:104-116",
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
        why: "Purge is not gated by `CanManageVault` — it is gated by `CanPurgeVault`, which checks a role assignment carrying `ActionVaultPurge`. The vault-scoped access policy from creation grants `vaults:manage` only, and the creator's Key Vault Administrator role assignment does not carry `ActionVaultPurge`. No built-in role does except Key Vault Purge Operator, so neither of Wren's two creator grants reaches this check.",
        after:
          "tenant-a stays soft-deleted and still counts against Wren's quota (3 of 3 used) — only an admin or a Key Vault Purge Operator grant can purge it and free the slot. Continuing this journey with Wren still short a slot hits the same quota-exceeded error V11 produced.",
        related: [
          { id: "J5", rel: "contrasts" },
          { id: "V13", rel: "depends" },
        ],
        source:
          "internal/services/authorization/vault_authz.go:61-73 (CanPurgeVault -> HasDataAction(ActionVaultPurge)); model/azure_roles.go:201-203; VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey V, step 5",
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
        why: "A provisioning grant confers authority to create vaults, nothing more. There is no access-policy row and no role assignment for Wren on `prod` at all, so `CanManageVault` falls through to its fail-closed default regardless of what she holds elsewhere.",
        source: "internal/services/authorization/vault_authz.go:35-55",
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
        notes: "The same trap for a test asserting the typed argument.",
        why: "Revoke resolves its argument through the same `resolvePrincipal` path as grant — UUID first, username fallback — so the printed line names the resolved principal, never the argument typed.",
        related: [{ id: "V1", rel: "depends" }],
        source: "cmd/vault-provisioning/revoke.go:19-33",
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
        why: "`requireCanCreateVault` calls `CanCreateVault`, which checks admin, then a global `vaults:manage` allow, then a provisioning grant, in that order. With the grant revoked and neither of the first two present, all three come back empty and the create is refused with the same three-way message a principal with no grant at all would see.",
        related: [{ id: "V16", rel: "depends" }],
        source:
          "cmd/vaults/authz.go:52-81; internal/services/authorization/vault_authz.go:171-195",
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
        why: "`RevokeGrant` deletes only the `vault_provisioning_grants` row. The vault-scoped access-policy allow and the Key Vault Administrator role assignment `CreateVaultProvisioned` wrote for tenant-b at creation are separate rows in separate tables, and revoke never touches them.",
        related: [{ id: "V16", rel: "depends" }],
        source: "internal/services/provisioning/grant_service.go:94-110",
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
        why: "`vaults get`/`delete` and `secrets list` check different things — `CanManageVault` against the vault-scoped access policy, `HasDataAction` against the Key Vault Administrator role assignment — and revoking a provisioning grant touches neither. Offboarding a principal means removing both, per vault, as a separate step.",
        related: [{ id: "V16", rel: "depends" }],
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey V, step 6",
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
        why: "`requireGrantAdmin` returns the authorized principal's ID, and `runGrant`/`runRevoke` pass it through to `IssueGrant`/`RevokeGrant` as the actor for the audit log entry — the CLI has no middleware that stamps an actor onto commands the way an HTTP session context does, so this return value is the only source of one.",
        source:
          "cmd/vault-provisioning/grant.go:41-58; internal/services/provisioning/grant_service.go:57-110",
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
        why: "`vault_id` is a plain `string` field on `CreateAccessPolicyRequest`; an empty value is what leaves the policy global. The stored `AccessPolicy.VaultID` is `*uuid.UUID` tagged `omitempty`, so a global policy's JSON response has no `vault_id` key at all rather than an explicit `null` — the missing key is what confirms 'global,' not a null value.",
        verify: {
          look: 'The `jq .` output has no `vault_id` key anywhere in the object — not `"vault_id": null`. The key must be fully absent, since the field is `omitempty`.',
        },
        source:
          "model/access_policy.go:64-66,79-80; model/access_policy.go:64-66",
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
          "It satisfies data-plane checks and nothing else, however much it looks like a substitute.",
        why: "`ExpandRole` returns `nil, nil` for every Azure built-in role, including Key Vault Administrator, because those roles are evaluated directly from the `role_assignments` row by `HasDataAction`, never materialized into `access_policies`. So this command writes a `role_assignments` row and nothing `CanManageVault` reads.",
        source: "internal/services/authorization/roles.go:155-168",
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
        why: "`CanCreateVault` checks a global `(vaults, manage, allow)` policy via `CheckAccess` at `vaultID == uuid.Nil` — the one call a `NULL`-scoped allow still satisfies. `CreateVaultProvisioned` treats this as `CreateRightGlobalPolicy`: not quota-bounded, but `grantCreatorRights` true.",
        source:
          "internal/services/authorization/vault_authz.go:171-195; internal/services/vaults/vault_service.go:355-361",
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
          "That asymmetry is the single most confusing thing about this release in practice, and it is intended.",
        why: "`vaults list` calls `CanManageVault` at `vaultID == uuid.Nil`, the same collection-level `CheckAccess` path create uses, and a `NULL`-scoped allow satisfies it — so she lists every vault. Listing is a collection-level decision; managing one is not, and that split is the entire point of this release.",
        verify: {
          look: "The list includes tenant-x — the vault she created — alongside vaults she has no management rights over at all, such as prod. Seeing a vault here is not evidence she can manage it.",
        },
        source:
          "cmd/vaults/authz.go:93-101; internal/services/authorization/vault_authz.go:35-55; VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey W, step 2",
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
        why: "`quotaBounded` is `false` for a global-policy creator — only a provisioning grant sets it `true` — and `CreateVaultProvisioned` refuses `PurgeProtection` only when `quotaBounded` is true. She has no quota to protect from being permanently occupied, so the restriction that blocks Journey V's grantee does not apply to her.",
        related: [{ id: "V12", rel: "contrasts" }],
        source: "internal/services/vaults/vault_service.go:355-374",
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
        why: "`cmd/vaults/create.go` passes `right != authz.CreateRightAdmin` as `grantCreatorRights`, true for her global-policy create. Inside the same transaction that inserts the vault, `CreateVaultProvisioned` writes a vault-scoped `(vaults, manage, allow)` access-policy row and a Key Vault Administrator role assignment for the creator — both scoped to this vault only. Each of these four commands checks one of those two grants, never the global policy itself.",
        source: "internal/services/vaults/vault_service.go:428-451",
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
        why: "The vault-scoped row is written by the same `CreatePolicyTx` call inside `CreateVaultProvisioned` that runs for every non-admin creator — it carries a concrete `vault_id`, unlike the pre-existing global row from W1, which has none.",
        related: [{ id: "W6", rel: "depends" }],
        source: "internal/services/vaults/vault_service.go:432-443",
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
        why: "A concrete vault ID routes `CanManageVault` to `CheckVaultScopedAccess` instead of `CheckAccess`. That method keeps every `NULL`-scoped **deny** row but discards `NULL`-scoped **allow** rows before returning a decision — her global allow is read from the database and then thrown away by the filter, so the check falls through to `AccessFallback`, which is not `AccessAllowed`, and `CanManageVault` fails closed.",
        related: [{ id: "W6", rel: "contrasts" }],
        source:
          "internal/services/authorization/access_policy_service.go:89-111",
      },
      {
        id: "W9",
        title: "Webhook configuration is denied the same way",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-webhook set --vault prod --url https://hooks.example/rocketvault`,
        expected: `Error: permission denied: managing webhook config for vault "prod" requires admin or vaults/manage`,
        assert: "Denied — webhook config is also behind CanManageVault",
        why: "Webhook configuration is gated by the same `CanManageVault` check as get/update/delete — one function, one narrowing, applied everywhere it is called.",
        source: "VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey W, step 4",
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
        why: "`CanManageRoleAssignments` was narrowed the same way and for the same reason as `CanManageVault`: it also routes a concrete vault ID to `CheckVaultScopedAccess`, discarding her `NULL`-scoped allow. Narrowing only `CanManageVault` would have left this open — role-assignment management alone is enough to self-award Key Vault Administrator in any vault, which is exactly what this command would do if it succeeded.",
        related: [{ id: "W2", rel: "contrasts" }],
        source: "internal/services/authorization/vault_authz.go:100-121",
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
          "The admin account role is untouched by any of this — it short-circuits both functions before any policy check runs.",
        why: "The asymmetry is deliberate and lives in one loop: `CheckVaultScopedAccess` returns `AccessDenied` the instant it sees **any** deny row, scoped or `NULL`, before it ever looks at allow rows — but it only honours an allow when it finds one scoped to this exact vault. A `NULL`-scoped deny is inspected first and always wins; a `NULL`-scoped allow is inspected last and never counts.",
        after:
          "This deny is global and blocks Iris everywhere, including tenant-x and tenant-y, until an admin removes it — `DELETE /api/v1/access-policies/{id}`, the same endpoint Journey H uses to lift an explicit deny. Nothing in this journey issues that call; do it before relying on Iris's global-policy access again.",
        related: [{ id: "W6", rel: "contrasts" }],
        source:
          "internal/services/authorization/access_policy_service.go:95-110; VAULT_USER_ACCESS_JOURNEYS_v3.md § Journey H",
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
        why: "Six subcommands — `vaults` `delete`/`get`/`recover`/`update` and `vault-webhook` `delete`/`get`/`set` — previously said an allow 'scoped to this vault or granted globally' would satisfy them. All six now say 'scoped to this vault,' matching the narrowing to `CheckVaultScopedAccess` described in step 4.",
        source:
          "cmd/vaults/delete.go:21; cmd/vaults/get.go:23; cmd/vaults/recover.go:22; cmd/vaults/update.go:25; cmd/vault-webhook/delete.go:23; cmd/vault-webhook/get.go:29; cmd/vault-webhook/set.go:35",
      },
    ],
  },
]
