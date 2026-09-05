/**
 * The material a tester needs beside the cases: the cast to create, the setup
 * to run once, the gates to tell apart, and the flag traps that waste an
 * afternoon. All transcribed from VAULT_USER_ACCESS_JOURNEYS_v3.md.
 */

export const setupScript = `# Point at your scratch instance, never a shared dev DB.
BASE=http://numericlabs.lxd/api/v1
export CFG=/tmp/rv-test.yaml

# TOTP is mandatory on every login.
export ROCKETVAULT_TOTP_SECRET=<the secret printed at user creation>
TOTP_CODE=$(go run scripts/totp_generator.go -secret="$ROCKETVAULT_TOTP_SECRET" \\
  2>&1 | grep -m1 -oP '(?<=--totp-code )\\S+')

# Log in once — the session caches under ~/.rocketvault/sessions and every
# other CLI command picks it up. HTTP does NOT read this cache; curl needs
# its own token.
rocketvault users login --username priya --password '<pw>' --totp-code "$TOTP_CODE"

ADMIN_TOKEN=$(curl -s -X POST $BASE/users/login \\
  -H "Content-Type: application/json" \\
  -d "{\\"username\\":\\"priya\\",\\"password\\":\\"<pw>\\",\\"totp_code\\":\\"$TOTP_CODE\\"}" \\
  | jq -r .token)`

export const globalFlags =
  "--config  --username  --password  --totp-code  --output {table|json|yaml}  --vault  --server  --ca-cert  --insecure-skip-verify"

export interface CastMember {
  name: string
  role: string
  why: string
}

export const cast: CastMember[] = [
  {
    name: "priya",
    role: "admin",
    why: "Bootstrap, user creation, vault creation, access policies, audit",
  },
  {
    name: "wren",
    role: "user",
    why: "Only ever grants and revokes role assignments — vault-access checks no global role",
  },
  {
    name: "sofia",
    role: "crypto_manager",
    why: "Must run keys create/rotate/sign from the CLI",
  },
  {
    name: "marcus",
    role: "secrets_manager",
    why: "Must run secrets create/update from the CLI",
  },
  {
    name: "daeho",
    role: "user",
    why: "Read-only via HTTP; keys list and get need no global role",
  },
  {
    name: "ops-oncall",
    role: "admin",
    why: "Second admin, for the separation-of-duties purge in Journey J",
  },
  {
    name: "noor",
    role: "certificate_manager",
    why: "Must run certificates create/update/delete/renew from the CLI",
  },
  {
    name: "ci-payments-svc",
    role: "service account",
    why: "OAuth2 client, REST only — never uses the CLI",
  },
  {
    name: "checkout-api-svc",
    role: "service account",
    why: "The narrowest crypto grant, in Journey E",
  },
]

export interface GateSpec {
  n: number
  key: string
  name: string
  scope: string
  signature: string
  detail: string
}

/**
 * The order matters and is the reason the diagram is numbered: gate 1 runs
 * before gate 2 runs before gate 3. A request refused at gate 1 never reaches
 * the vault check, which is what makes Journey P's contrast possible.
 */
export const gates: GateSpec[] = [
  {
    n: 1,
    key: "global-role",
    name: "Global role",
    scope: "CLI only — no HTTP equivalent",
    signature: "forbidden: requires admin or crypto_manager role",
    detail:
      "Every mutating keys, secrets and certificate command checks a global role before it looks at any vault. HTTP data-plane routes bypass global RBAC entirely, so this gate simply does not exist over REST.",
  },
  {
    n: 2,
    key: "explicit-deny",
    name: "Explicit deny",
    scope: "Both doors",
    signature: "Forbidden: access policy denied",
    detail:
      "An access policy with effect deny, evaluated before any role grant is consulted. Admin-only to create, and HTTP-only — there is no CLI command for it.",
  },
  {
    n: 3,
    key: "vault-role",
    name: "Vault role",
    scope: "Both doors — no admin short-circuit",
    signature: "forbidden: no role grants <action> in this vault",
    detail:
      "Deny-by-default per-vault role assignment. HasDataAction has no admin bypass by design, so a global admin who created the vault is refused inside it until they grant themselves a role.",
  },
]

export interface ErrorRow {
  message: string
  gate: string
}

export const errorTable: ErrorRow[] = [
  {
    message: "forbidden: requires admin or crypto_manager role",
    gate: "Gate 1 — CLI-only global role. No HTTP equivalent.",
  },
  {
    message: "Forbidden: access policy denied",
    gate: "Gate 2 — explicit deny, rejected before the role check ran.",
  },
  {
    message:
      "forbidden: no role grants <action> in this vault  /  Forbidden: no role assignment grants this operation in this vault",
    gate: "Gate 3 — deny-by-default. Applies to global admins too.",
  },
  {
    message:
      "Insufficient permissions: admin role required to manage access policies",
    gate: "The access-policy surface, admin-only.",
  },
  {
    message:
      "permission denied: admin, vaults/manage, or Key Vault Data Access Administrator required for this vault",
    gate: "Vault-management tier — CanManageVault, not a data-plane role.",
  },
  {
    message: "grant failed: role cannot be granted by a non-admin caller",
    gate: "ErrRoleNotGrantable — outside Data Access Administrator's eight-role allow-list.",
  },
]

export interface CommandGroup {
  group: string
  subcommands: string
}

export const commandGroups: CommandGroup[] = [
  {
    group: "users",
    subcommands:
      "admin | create | get | list | update | delete | login | logout",
  },
  {
    group: "vaults",
    subcommands:
      "create | list | get | update | delete | recover | purge | preview-migration",
  },
  { group: "vault-access", subcommands: "roles | grant | revoke | list" },
  { group: "vault-webhook", subcommands: "get | set | delete" },
  {
    group: "keys",
    subcommands:
      "create | get | list | update | delete | rotate | sign | verify | wrap | unwrap",
  },
  { group: "keys rotation-policy", subcommands: "get | set | delete" },
  {
    group: "secrets",
    subcommands:
      "create | get | list | update | delete | export | import | generate-password",
  },
  {
    group: "secrets rotation",
    subcommands:
      "create | list | update | delete | assign | unassign | rotate | history | status",
  },
  {
    group: "certificates",
    subcommands:
      "create | list | get | update | delete | renew   (certificate also works)",
  },
  { group: "audit", subcommands: "logs | report | config" },
  { group: "backup", subcommands: "create | list | restore" },
  {
    group: "context",
    subcommands: "add | list | use | current | remove | unset",
  },
  { group: "master-key", subcommands: "rotate" },
]

export interface FlagTrap {
  command: string
  gotcha: string
}

export const flagTraps: FlagTrap[] = [
  {
    command: "vaults create/delete/recover/purge/update",
    gotcha: "The vault name is positional. These have no --vault flag.",
  },
  {
    command: "users create --new-role",
    gotcha: "Repeatable, not comma-separated.",
  },
  {
    command: "keys create --bits",
    gotcha:
      "Help says 2048 or 4096; 3072 is also valid. Invalid sizes are rejected only after a full authenticated round trip, never at flag-parse time.",
  },
  {
    command: "keys create --curve",
    gotcha:
      'Help omits P-256K, which works. A P-256K key is stored with type ES256K, not ECDSA — tooling asserting type == "ECDSA" misses them silently.',
  },
  {
    command: "keys create --type",
    gotcha:
      "Accepts only RSA and ECDSA. --type ES256K is rejected; reach it via --type ECDSA --curve P-256K.",
  },
  {
    command: "keys create (name)",
    gotcha:
      "The CLI validates almost nothing; HTTP enforces ^[a-zA-Z][a-zA-Z0-9-]{0,126}$. A CLI-created key can violate a constraint HTTP would reject.",
  },
  {
    command: "keys wrap/unwrap",
    gotcha:
      "No --algorithm flag — always RSA-OAEP. AES key wrapping is REST-only.",
  },
  {
    command: "keys rotation-policy set",
    gotcha:
      "--rotate-after-days and --enabled are both required on every call. It is a full replace, not a partial update.",
  },
  {
    command: "keys sign/verify/wrap/unwrap --version",
    gotcha: "0 or omitted means the current version.",
  },
  {
    command: "Duplicate key name",
    gotcha:
      "Rejected only after RSA generation runs, with a raw driver error (UNIQUE constraint failed: keys.vault_id, keys.name on SQLite).",
  },
  {
    command: "secrets rotation --auto-rotate",
    gotcha:
      "The scheduler replaces the live value with a generated one. Nothing outside RocketVault is told.",
  },
  {
    command: "backup create --file",
    gotcha:
      "The destination is --file/-f. --output is root's persistent table/json/yaml selector and will fail format validation.",
  },
  {
    command: "--server / ROCKETVAULT_ADDR",
    gotcha:
      "Not supported by every subcommand. The authority is the remoteCapableCommands map in cmd/root.go, not any document.",
  },
  {
    command: "vault-provisioning grant --quota",
    gotcha:
      'Documented as required but not registered required with cobra — it is a plain Int flag defaulting to 0, so omitting it gives the positive-integer error, not required flag(s) "quota" not set.',
  },
  {
    command: "vault-provisioning grant/revoke",
    gotcha:
      "Print the resolved principal UUID, never the username you typed. A test asserting the literal argument fails on a correct build.",
  },
  {
    command: "vault-provisioning list",
    gotcha:
      "Ignores both --vault and --output — it writes with fmt.Fprintf and never reaches the output formatter, unlike vaults list.",
  },
  {
    command: "HTTP -HSM type suffix",
    gotcha:
      "buildKeyResponse appends -HSM for PKCS#11-backed keys. keys list --output json still prints plain RSA/ECDSA — the suffix is added by the HTTP handler only.",
  },
]

export interface Correction {
  n: number
  claimed: string
  actual: string
}

export const corrections: Correction[] = [
  {
    n: 1,
    claimed: "Global admin bypasses all vault checks.",
    actual:
      "False. HasDataAction has no admin short-circuit. Admins must self-grant a role in each vault.",
  },
  {
    n: 2,
    claimed: "Cross-vault access returns 404.",
    actual: "It returns 403 deny-by-default.",
  },
  {
    n: 3,
    claimed: "Crypto User can use a key but not manage it.",
    actual: "It also has update and backup, added 2026-08-18.",
  },
  {
    n: 4,
    claimed: "Data Access Administrator manages access generally.",
    actual:
      "Role assignments only. Access policies are a separate, admin-only surface.",
  },
  {
    n: 5,
    claimed: "Revocation is immediate for new requests.",
    actual:
      "Confirmed precisely: the same token, with byte-identical claims, goes 200 to 403.",
  },
  {
    n: 6,
    claimed: "Purging a vault cleans it up.",
    actual:
      "It does not cascade, and permanently orphans the vault's children.",
  },
  {
    n: 7,
    claimed: "Crypto Officer can import keys.",
    actual: "ActionKeysImport is in the bundle, but no route maps to it.",
  },
  {
    n: 8,
    claimed: "The CLI and HTTP enforce the same authorization.",
    actual:
      "The CLI adds a global role gate that has no HTTP equivalent. A user with Key Vault Crypto Officer in prod can create a key over REST and is refused by the CLI.",
  },
  {
    n: 9,
    claimed: "The CLI covers the key lifecycle.",
    actual:
      "Key recover, purge, backup and restore have no CLI command at all, and OCT key creation is REST-only.",
  },
]

export interface CapabilityRow {
  capability: string
  cli: string
  http: string
}

export const capabilityMatrix: CapabilityRow[] = [
  {
    capability: "Key soft-delete",
    cli: "keys delete",
    http: "DELETE /vaults/{v}/keys/{id}",
  },
  {
    capability: "Key recover",
    cli: "none",
    http: "/deleted/keys/{id}/restore",
  },
  { capability: "Key purge", cli: "none", http: "/deleted/keys/{id}/purge" },
  {
    capability: "Key backup / restore",
    cli: "none",
    http: "/keys/{id}/backup, /keys/restore",
  },
  {
    capability: "Key rotation policy",
    cli: "keys rotation-policy get/set/delete",
    http: "GET/PUT/DELETE .../rotationpolicy",
  },
  {
    capability: "Secret rotation policy",
    cli: "secrets rotation *",
    http: "none",
  },
  {
    capability: "OCT (AES) key creation",
    cli: "none",
    http: 'POST /keys {"type":"OCT"} — HSM-only',
  },
  {
    capability: "Certificate recover / purge",
    cli: "none",
    http: "/deleted/certificates/{id}/…",
  },
  {
    capability: "Explicit-deny access policy",
    cli: "none",
    http: "/access-policies",
  },
]
