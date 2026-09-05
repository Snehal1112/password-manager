import type { Suite } from "./types"

export const journeysAF: Suite[] = [
  {
    key: "A",
    title: "Day zero: the admin discovers she has no access",
    actor: "Priya — global role admin",
    premise:
      "Creating a vault is a management operation. Everything inside it is not. The admin who just created `prod` cannot read a thing in it until she grants herself a role, because `HasDataAction` has no admin short-circuit by design.",
    cases: [
      {
        id: "A1",
        title: "Bootstrap the first admin with the one-time token",
        surface: "cli",
        gate: "none",
        precondition:
          "A clean instance with no users. The bootstrap token comes from your own `.rocketvault.yaml` — it is generated per clone, never committed.",
        command: `rocketvault users admin \\
  --admin-username priya \\
  --admin-password '<pw>' \\
  --bootstrap-token '<token-from-config>'`,
        expected: "The TOTP secret is printed exactly once. Capture it now.",
        assert: "Succeeds with no prior session; prints TOTP secret once",
        notes:
          "This is the only command that needs no session. Losing the printed secret means recreating the user.",
      },
      {
        id: "A2",
        title: "Log in and cache the session",
        surface: "cli",
        gate: "none",
        command: `rocketvault users login --username priya --password '<pw>' --totp-code "$TOTP_CODE"`,
        expected: "Login successful as priya.",
        assert: "Session cached under ~/.rocketvault/sessions",
        notes:
          "Every later CLI command picks this up with no credential flags. HTTP does **not** read this cache — curl needs its own token.",
      },
      {
        id: "A3",
        title: "Create the three vaults; the name is positional",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults create dev
rocketvault vaults create staging
rocketvault vaults create prod --purge-protection --retention-days 30`,
        expected: "Three vaults created.",
        assert: "Positional name accepted; no --vault flag exists here",
        notes:
          "`vaults create/delete/recover/purge/update` all take the name positionally. Passing `--vault` instead is a common early mistake.",
      },
      {
        id: "A4",
        title: "List and inspect the new vaults",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults list
rocketvault vaults get prod --output json`,
        expected:
          "`prod` reports purge protection enabled and 30-day retention.",
        assert: "Creation flags round-trip into the stored record",
      },
      {
        id: "A5",
        title: "Update only the attributes actually passed",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults update staging --retention-days 14
rocketvault vaults update staging --purge-protection`,
        expected:
          "Retention becomes 14 on the first call; purge protection turns on in the second, with retention still 14.",
        assert: "An omitted flag leaves its field unchanged",
        notes:
          "This is a partial update, unlike `keys rotation-policy set`, which is a full replace. The two behave differently on purpose.",
      },
      {
        id: "A6",
        title: "preview-migration refuses to run against a remote server",
        surface: "cli",
        gate: "management",
        precondition: "Only relevant when upgrading a pre-P2 install.",
        command: `rocketvault vaults preview-migration --server https://vault.prod.internal`,
        expected: "Refused — it reads the local database file directly.",
        assert: "Rejects --server rather than guessing",
        notes:
          "It writes nothing. Confirm every principal that needs access appears in its output **before** running the real migration, not after.",
      },
      {
        id: "A7",
        title: "The vault's own creator is denied inside it",
        surface: "cli",
        gate: "vault-role",
        precondition:
          "Priya has created `prod` and holds no role assignment in it.",
        command: `rocketvault keys list --vault prod`,
        expected:
          "Error: forbidden: no role grants Microsoft.KeyVault/vaults/keys/read/action in this vault",
        assert: "Denied — global admin does not bypass the vault check",
        flag: "trap",
        notes:
          "The single most surprising behaviour in RocketVault, and correct. Retract any runbook that says admin bypasses vault checks.",
      },
      {
        id: "A8",
        title: "The same denial over HTTP",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' $BASE/vaults/prod/secrets \\
  -H "Authorization: Bearer $ADMIN_TOKEN"`,
        expected: "403",
        assert: "403, not 404 and not 200",
        notes:
          "Both doors agree here. Journeys K and P are where they stop agreeing.",
      },
      {
        id: "A9",
        title: "Self-grant Key Vault Administrator in each vault",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant priya --role "Key Vault Administrator" --vault prod
rocketvault vault-access grant priya --role "Key Vault Administrator" --vault dev
rocketvault vault-access grant priya --role "Key Vault Administrator" --vault staging`,
        expected: "Three assignments created, each with its own id.",
        assert: "Grant succeeds and returns an assignment id",
      },
      {
        id: "A10",
        title: "The denied command now works",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault keys list --vault prod`,
        expected: "An empty list, not a forbidden error.",
        assert: "Same command as A7, now permitted",
        notes:
          "Put “self-grant Key Vault Administrator in every new vault” in your provisioning runbook, or the vault is unusable to whoever created it.",
      },
      {
        id: "A11",
        title: "Create the team with the global roles the CLI requires",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault users create --new-username wren   --new-password '<pw>' --new-role user
rocketvault users create --new-username sofia  --new-password '<pw>' --new-role crypto_manager
rocketvault users create --new-username marcus --new-password '<pw>' --new-role secrets_manager
rocketvault users create --new-username daeho  --new-password '<pw>' --new-role user
rocketvault users create --new-username ops-oncall --new-password '<pw>' --new-role admin`,
        expected: "Each command prints a TOTP secret exactly once.",
        assert: "Five users created; five TOTP secrets captured",
        notes:
          "Capture every secret as it appears. The rest of this playbook cannot be run without them.",
      },
      {
        id: "A12",
        title: "--new-role is repeatable, not comma-separated",
        surface: "cli",
        gate: "validation",
        command: `rocketvault users create --new-username multi --new-password '<pw>' \\
  --new-role admin --new-role secrets_manager`,
        expected: "A user holding both roles.",
        assert: "Two --new-role flags produce two roles",
        notes:
          "`--new-role admin,secrets_manager` does not split into two roles. Check what actually landed with `users list --output json`.",
      },
    ],
  },
  {
    key: "B",
    title: "Onboarding a backend engineer, one role at a time",
    actor: "Marcus — global role secrets_manager",
    premise:
      "Reader, then Secrets User, then Secrets Officer. Each step should unlock exactly one more thing and nothing else, and none of them should reach `prod`.",
    cases: [
      {
        id: "B1",
        title: "Week 1: Reader sees metadata",
        surface: "cli",
        gate: "vault-role",
        precondition: `rocketvault vault-access grant marcus --role "Key Vault Reader" --vault dev`,
        command: `rocketvault secrets list --vault dev`,
        expected: "The list renders — names, tags, timestamps.",
        assert: "Listing works under Reader",
      },
      {
        id: "B2",
        title: "Reader cannot read a secret value",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault secrets get <secret-id> --vault dev`,
        expected: "Error: forbidden — Reader has no secrets/get",
        assert: "Denied; Reader holds readMetadata, not secrets/get",
      },
      {
        id: "B3",
        title: "Reader must not see values in the versions list",
        surface: "http",
        gate: "vault-role",
        precondition:
          "This is the § B30 regression check. Run it on every release.",
        command: `curl -s $BASE/vaults/dev/secrets/<secret-id>/versions \\
  -H "Authorization: Bearer $MARCUS_TOKEN" | jq '[.versions[] | has("value")] | any'`,
        expected: "false",
        assert: "Prints exactly false",
        flag: "trap",
        notes:
          "A `true` here means secret values are leaking to a metadata-only role through the versions endpoint. Treat it as a release blocker, not a bug report.",
      },
      {
        id: "B4",
        title: "Week 2: swap Reader for Secrets User",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access revoke <reader-assignment-id> --vault dev
rocketvault vault-access grant marcus --role "Key Vault Secrets User" --vault dev`,
        expected: "The Reader assignment is gone; a Secrets User one exists.",
        assert: "Revoke then grant both succeed",
      },
      {
        id: "B5",
        title: "Secrets User can now read the value",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault secrets get <secret-id> --vault dev --output json`,
        expected: "The response carries the decrypted value.",
        assert: "Value returned — the same call that failed in B2",
      },
      {
        id: "B6",
        title: "Secrets User still cannot write",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault secrets create test-db-pass 's3cr3t' --vault dev`,
        expected: "Error: forbidden (no secrets/set)",
        assert: "Denied at the vault-role gate, not the global-role gate",
        notes:
          "Marcus holds `secrets_manager` globally, so Correction 8's gate passes. This denial comes from the vault role, which proves the two gates are independent.",
      },
      {
        id: "B7",
        title: "Month 3: Secrets Officer writes, updates and filters",
        surface: "cli",
        gate: "vault-role",
        precondition: `rocketvault vault-access grant marcus --role "Key Vault Secrets Officer" --vault dev`,
        command: `rocketvault secrets create db-pass 's3cr3t-v1' --tags prod,db --vault dev
rocketvault secrets update <secret-id> 's3cr3t-v2' --vault dev
rocketvault secrets list --vault dev --tags prod --output json`,
        expected: "Create and update succeed; the tag filter returns db-pass.",
        assert: "Full secret ownership in dev",
      },
      {
        id: "B8",
        title: "Still nothing in prod",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault secrets list --vault prod`,
        expected: "Error: forbidden: no role grants ... in this vault",
        assert: "Three grants in dev buy nothing in prod",
      },
      {
        id: "B9",
        title: "Re-granting the same role is harmless",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant marcus --role "Key Vault Secrets Officer" --vault dev`,
        expected: "The original assignment id is returned, not a new one.",
        assert: "Idempotent — no duplicate row, no error",
        notes:
          "`AssignRole` finds the existing `(principal, role, vault)` tuple. Safe to put in a provisioning script that may re-run.",
      },
      {
        id: "B10",
        title: "A user can read and update their own account",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault users get <marcus-user-id>
rocketvault users update <marcus-user-id> --new-password 'new-Str0ng-pw'`,
        expected: "Both succeed — owner-or-admin, with no vault scoping.",
        assert: "Own profile is readable and writable",
        notes:
          "User accounts are global. There is no vault-scoped user, so `--vault` does nothing here.",
      },
      {
        id: "B11",
        title: "A user cannot read someone else's account",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault users get <sofia-user-id>`,
        expected:
          "Error: forbidden: can only access your own profile or requires admin role",
        assert: "Denied on another principal's record",
      },
      {
        id: "B12",
        title: "A user cannot grant themselves a global role",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault users update <marcus-user-id> --new-role admin`,
        expected: "Error: forbidden: only admins can change roles",
        assert: "Self-escalation blocked even on your own record",
        flag: "trap",
        notes:
          "Note the shape: he *can* update his own record, but not that field of it. A test asserting only “update succeeds” would miss this.",
      },
    ],
  },
  {
    key: "C",
    title: "Security engineer owns the key lifecycle",
    actor: "Sofia — global role crypto_manager",
    premise:
      "Every mutating `keys` command needs `admin` or `crypto_manager` globally, on top of the vault role. This journey walks create, sign, verify, update, rotate and rotation policy, and ends at three capabilities that do not exist.",
    cases: [
      {
        id: "C1",
        title: "Create an RSA key with tags and purge protection",
        surface: "cli",
        gate: "global-role",
        precondition: `rocketvault vault-access grant sofia --role "Key Vault Crypto Officer" --vault prod`,
        command: `rocketvault keys create --name payments-signing --type RSA --bits 4096 \\
  --tags prod,jwt --purge-protection --vault prod`,
        expected: "The key is created and its id printed.",
        assert: "Create succeeds with crypto_manager + Crypto Officer",
      },
      {
        id: "C2",
        title: "Create an ECDSA key on P-384",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys create --name payments-ec --type ECDSA --curve P-384 \\
  --tags prod --vault prod`,
        expected: "The key is created.",
        assert: "P-384 accepted",
      },
      {
        id: "C3",
        title: "P-256K works but is stored as ES256K, not ECDSA",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys create --name secp-key --type ECDSA --curve P-256K --vault prod
rocketvault keys get <secp-key-id> --vault prod --output json | jq .type`,
        expected: '"ES256K"',
        assert: "Type reads ES256K, not ECDSA",
        flag: "trap",
        notes:
          '`--curve`\'s help omits P-256K entirely, and `--type ES256K` is rejected — reach it only via `--type ECDSA --curve P-256K`. Tooling that asserts `type == "ECDSA"` misses these keys silently.',
      },
      {
        id: "C4",
        title: "3072-bit keys work despite the help text",
        surface: "cli",
        gate: "validation",
        command: `rocketvault keys create --name rsa-3072 --type RSA --bits 3072 --vault prod`,
        expected: "The key is created.",
        assert: "3072 accepted even though --help says 2048 or 4096",
        flag: "gap",
      },
      {
        id: "C5",
        title: "An invalid key size fails only after a full round trip",
        surface: "cli",
        gate: "validation",
        command: `rocketvault keys create --name rsa-bad --type RSA --bits 1234 --vault prod`,
        expected:
          "Rejected — but only after authenticating, never at parse time.",
        assert: "Rejected late, not at flag-parse time",
        flag: "gap",
      },
      {
        id: "C6",
        title: "Sign and verify a payload",
        surface: "cli",
        gate: "none",
        command: `DATA=$(echo -n '{"sub":"txn-1"}' | base64)

SIG=$(rocketvault keys sign --key-id <key-id> --data "$DATA" \\
        --algorithm RS256 --vault prod)

rocketvault keys verify --key-id <key-id> --data "$DATA" \\
  --signature "$SIG" --algorithm RS256 --vault prod`,
        expected: "valid: true",
        assert: "Round trip verifies",
      },
      {
        id: "C7",
        title: "A tampered payload fails verification",
        surface: "cli",
        gate: "none",
        command: `TAMPERED=$(echo -n '{"sub":"attacker"}' | base64)
rocketvault keys verify --key-id <key-id> --data "$TAMPERED" \\
  --signature "$SIG" --algorithm RS256 --vault prod`,
        expected: "valid: false",
        assert: "valid: false — a clean answer, not an error",
      },
      {
        id: "C8",
        title: "Update mutable attributes without touching key material",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys update <key-id> --tags prod,jwt,q3-review --vault prod`,
        expected: "Key <key-id> updated successfully at 2026-08-25T...",
        assert: "Tags change; key material does not",
      },
      {
        id: "C9",
        title: "Revoking breaks crypto but leaves metadata readable",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys update <key-id> --revoked --vault prod
rocketvault keys sign --key-id <key-id> --data "$DATA" --algorithm RS256 --vault prod`,
        expected: "Error: ... key is revoked",
        assert: "Sign fails; keys get still returns the record",
      },
      {
        id: "C10",
        title: "Un-revoke with an explicit false",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys update <key-id> --revoked=false --vault prod`,
        expected: "The key signs again.",
        assert: "--revoked=false restores the key",
        notes:
          "The `=false` form is required. A bare `--revoked` sets it true.",
      },
      {
        id: "C11",
        title: "keys update requires at least one field",
        surface: "cli",
        gate: "validation",
        command: `rocketvault keys update <key-id> --vault prod`,
        expected:
          "Error: at least one update field (name, revoked, tags, purge-protection) must be provided",
        assert: "Empty update rejected rather than treated as a no-op",
      },
      {
        id: "C12",
        title: "Old key versions still verify after a rotation",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys rotate <key-id> --vault prod

rocketvault keys verify --key-id <key-id> --data "$DATA" \\
  --signature "$SIG" --algorithm RS256 --version 1 --vault prod`,
        expected:
          "valid: true — the signature made before rotation still verifies",
        assert: "--version 1 reaches the pre-rotation material",
        notes:
          "`--version 0` or an omitted `--version` means the current version. This is the assertion that proves rotation is additive, not destructive.",
      },
      {
        id: "C13",
        title: "A key with no rotation policy reports, rather than errors",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys rotation-policy get <key-id> --vault prod`,
        expected: "No rotation policy set for key <key-id>",
        assert: "Exit is clean; the message is informational",
      },
      {
        id: "C14",
        title: "rotation-policy set is a full replace, not a partial update",
        surface: "cli",
        gate: "validation",
        command: `rocketvault keys rotation-policy set <key-id> --vault prod`,
        expected: `Error: --rotate-after-days and --enabled are required: this replaces the
whole policy, so every field must be supplied`,
        assert: "Missing flags are a validation error, not “leave unchanged”",
        flag: "trap",
        notes:
          "Contrast with `vaults update` (A5), which *is* a partial update. The two are inconsistent by design — mirror the HTTP `PUT` semantics here.",
      },
      {
        id: "C15",
        title: "Azure parity: rotate-after-days must be at least 7",
        surface: "cli",
        gate: "validation",
        command: `rocketvault keys rotation-policy set <key-id> --rotate-after-days 3 --enabled --vault prod`,
        expected: `Error: invalid rotation policy: RotateAfterDays: must be at least 7 when
the policy is enabled.`,
        assert: "Rejected below 7 days when enabled",
      },
      {
        id: "C16",
        title: "Set a full rotation policy",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault keys rotation-policy set <key-id> --vault prod \\
  --rotate-after-days 90 --notify-before-expiry-days 14 --expiry-days 365 --enabled`,
        expected:
          "Rotation policy set for key <key-id>: next rotation at 2026-11-23T...",
        assert: "Policy stored; next rotation date computed",
      },
      {
        id: "C17",
        title: "The HTTP PUT has the same full-replace contract",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -X PUT $BASE/vaults/prod/keys/<key-id>/rotationpolicy \\
  -H "Authorization: Bearer $SOFIA_TOKEN" -H "Content-Type: application/json" \\
  -d '{"rotate_after_days":90,"notify_before_expiry_days":14,
       "expiry_days":365,"enabled":true}' | jq .`,
        expected: "The stored policy, echoed back.",
        assert: "All four fields required; an omitted one zeroes itself",
        flag: "trap",
        notes:
          "An omitted field silently zeroes rather than leaving the stored value alone. Same trap as C14, different door.",
      },
      {
        id: "C18",
        title: "notify_before_expiry_days is stored and never read",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys rotation-policy get <key-id> --vault prod --output json`,
        expected:
          "The field echoes back the 14 set in C16. Nothing ever sends a notification.",
        assert: "Value round-trips; no notification is ever delivered",
        flag: "gap",
        notes:
          "There is no outbound HTTP anywhere in the vault, secret or key service packages. Per-vault webhook *config* exists (Journey U) but nothing sends. Do not build an operational process that depends on RocketVault warning you before expiry.",
      },
      {
        id: "C19",
        title: "Deleting the policy stops the scheduler, not the key",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault keys rotation-policy delete <key-id> --vault prod`,
        expected: "Rotation policy for key <key-id> deleted successfully",
        assert: "Policy gone; manual keys rotate still works",
      },
      {
        id: "C20",
        title: "Deleting a policy twice errors the second time",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys rotation-policy delete <key-id> --vault prod`,
        expected: "Error: no rotation policy exists for key <key-id>",
        assert: "Not idempotent — contrast with vault-webhook delete (U8)",
      },
      {
        id: "C21",
        title: "Key import does not exist",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys import ...`,
        expected: 'Error: unknown command "import" for "rocketvault keys"',
        assert: "Unknown command",
        flag: "gap",
        notes:
          "`ActionKeysImport` is in the Crypto Officer bundle, but no route maps to it either. The permission exists; the capability does not.",
      },
      {
        id: "C22",
        title: "A duplicate key name leaks a raw driver error",
        surface: "cli",
        gate: "none",
        command: `rocketvault keys create --name payments-signing --type RSA --bits 4096 --vault prod`,
        expected:
          "UNIQUE constraint failed: keys.vault_id, keys.name  (on SQLite)",
        assert: "Rejected only after RSA generation, with an unwrapped error",
        flag: "gap",
        notes:
          "The name collision is detected after the expensive key generation runs. If you script this, match on `UNIQUE constraint failed` rather than a friendly message.",
      },
      {
        id: "C23",
        title: "The CLI barely validates key names; HTTP does",
        surface: "both",
        gate: "validation",
        command: `rocketvault keys create --name '9-starts-with-a-digit' --type RSA --bits 2048 --vault prod`,
        expected:
          "The CLI accepts it. HTTP enforces ^[a-zA-Z][a-zA-Z0-9-]{0,126}$ and would reject it.",
        assert: "A CLI-created key can violate a constraint HTTP enforces",
        flag: "divergence",
      },
    ],
  },
  {
    key: "D",
    title: "CI/CD service account, sign-only",
    actor: "ci-payments-svc — REST only",
    premise:
      "A service account's grant runs the same `HasDataAction` codepath as a human's, with the same per-vault scoping. Service accounts never touch the CLI session cache.",
    cases: [
      {
        id: "D1",
        title: "Grant a role to a service account",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant ci-payments-svc --role "Key Vault Crypto User" \\
  --principal-type service_account --vault prod`,
        expected: "The assignment is created.",
        assert: "--principal-type service_account accepted",
        notes:
          "Omitting `--principal-type` treats the name as a user, which will not match the service account.",
      },
      {
        id: "D2",
        title: "The assignment appears in the vault listing",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access list --vault prod --output json`,
        expected: "An entry with principal_username ci-payments-svc.",
        assert: "Service account listed alongside human principals",
      },
      {
        id: "D3",
        title: "Obtain a token by client-credentials grant",
        surface: "http",
        gate: "none",
        command: `SVC_TOKEN=$(curl -s -X POST $BASE/oauth2/token \\
  -H "Content-Type: application/json" \\
  -d '{"grant_type":"client_credentials",
       "client_id":"ci-payments-svc","client_secret":"'"$VAULT_CLIENT_SECRET"'"}' \\
  | jq -r .access_token)`,
        expected: "A JWT.",
        assert: "Token issued with no TOTP and no session file",
      },
      {
        id: "D4",
        title: "Crypto User can sign",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -X POST $BASE/vaults/prod/keys/<key-id>/sign \\
  -H "Authorization: Bearer $SVC_TOKEN" -H "Content-Type: application/json" \\
  -d '{"value":"'"$DATA"'","algorithm":"RS256"}' | jq -r .value`,
        expected: "A signature.",
        assert: "200 with a signature body",
      },
      {
        id: "D5",
        title: "Crypto User cannot create a key",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' -X POST $BASE/vaults/prod/keys \\
  -H "Authorization: Bearer $SVC_TOKEN" -H "Content-Type: application/json" \\
  -d '{"name":"scratch","type":"RSA","bits":2048}'`,
        expected: "403",
        assert: "403 — Crypto User has no keys/create",
      },
      {
        id: "D6",
        title: "Crypto User does include update and backup",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' -X POST $BASE/vaults/prod/keys/<key-id>/backup \\
  -H "Authorization: Bearer $SVC_TOKEN"`,
        expected: "200 — a master-key-encrypted blob, not plaintext PEM.",
        assert: "Backup permitted under Crypto User",
        flag: "trap",
        notes:
          "Threat-model precision: the blob is ciphertext, but it is still key material. “Can use a key, can't manage it” is not an accurate description of this role.",
      },
    ],
  },
  {
    key: "E",
    title: "The narrowest possible crypto grant",
    actor: "checkout-api-svc — Crypto Service Encryption User",
    premise:
      "Wrap and unwrap, and nothing else. The failure that matters is what happens when a buggy client calls `encrypt` instead of `wrap`.",
    cases: [
      {
        id: "E1",
        title: "Grant the encryption-user role",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant checkout-api-svc \\
  --role "Key Vault Crypto Service Encryption User" \\
  --principal-type service_account --vault prod`,
        expected: "The assignment is created.",
        assert: "Role name accepted verbatim",
      },
      {
        id: "E2",
        title: "Wrap/unwrap round-trips over the CLI",
        surface: "cli",
        gate: "none",
        precondition: "Run as an operator, to demonstrate the shape.",
        command: `MATERIAL=$(openssl rand -base64 32)

WRAPPED=$(rocketvault keys wrap --key-id <rsa-key-id> \\
            --key-material "$MATERIAL" --vault prod)

rocketvault keys unwrap --key-id <rsa-key-id> \\
  --wrapped-key "$WRAPPED" --vault prod`,
        expected: "The original $MATERIAL, printed back.",
        assert: "Unwrap returns the input byte-for-byte",
      },
      {
        id: "E3",
        title: "The CLI always requests RSA-OAEP",
        surface: "cli",
        gate: "validation",
        command: `rocketvault keys wrap --key-id <rsa-key-id> --key-material "$MATERIAL" \\
  --algorithm AES-KW --vault prod`,
        expected: "Unknown flag — there is no --algorithm on wrap or unwrap.",
        assert: "No --algorithm flag exists",
        flag: "gap",
        notes: "AES key wrapping is REST-only.",
      },
      {
        id: "E4",
        title: "The service can wrap over HTTP",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -X POST $BASE/vaults/prod/keys/<key-id>/wrap \\
  -H "Authorization: Bearer $CHECKOUT_TOKEN" -H "Content-Type: application/json" \\
  -d '{"plaintext_key":"'"$MATERIAL"'","algorithm":"RSA-OAEP"}' | jq -r .wrapped_key`,
        expected: "The wrapped key.",
        assert: "200 with wrapped_key",
      },
      {
        id: "E5",
        title: "Calling encrypt instead of wrap fails closed",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' -X POST $BASE/vaults/prod/keys/<key-id>/encrypt \\
  -H "Authorization: Bearer $CHECKOUT_TOKEN" -H "Content-Type: application/json" \\
  -d '{"algorithm":"RSA-OAEP-256","value":"'"$DATA"'"}'`,
        expected: "403",
        assert: "403 — this role has no keys/encrypt",
        notes:
          "The point of the case: a bug that hits the wrong endpoint is refused rather than silently doing different crypto.",
      },
      {
        id: "E6",
        title: "CBC modes are rejected on wrap, allowed on encrypt",
        surface: "http",
        gate: "validation",
        precondition: "HSM-backed keys only.",
        command: `# wrap with A256CBC -- rejected
# encrypt/decrypt with A256CBC -- accepted, and round-trips the IV`,
        expected:
          "Wrap refuses A128CBC/A192CBC/A256CBC; encrypt and decrypt accept them.",
        assert: "The wrap contract carries no IV channel",
        notes:
          "On HSM-backed keys wrap/unwrap is limited to AES-KW and the RSA-OAEP variants. This is a contract limit, not an authorization one.",
      },
    ],
  },
  {
    key: "F",
    title: "Crypto User hits the rotation-policy wall",
    actor: "cryptouser — Key Vault Crypto User and nothing else",
    premise:
      "The whole journey exists for one contrast: the same route returns 403 for this principal and 404 for an admin. A test asserting only “non-200” cannot tell a denial from an empty resource.",
    cases: [
      {
        id: "F1",
        title: "Grant Crypto User and nothing else",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant cryptouser --role "Key Vault Crypto User" --vault prod`,
        expected: "One assignment.",
        assert: "Exactly one role held in prod",
      },
      {
        id: "F2",
        title: "Crypto User can encrypt",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -X POST $BASE/vaults/prod/keys/<key-id>/encrypt \\
  -H "Authorization: Bearer $CU_TOKEN" -H "Content-Type: application/json" \\
  -d '{"algorithm":"RSA-OAEP-256","value":"'"$DATA"'"}'`,
        expected: "200",
        assert: "200",
      },
      {
        id: "F3",
        title: "Crypto User gained update on 2026-08-18",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -X PUT $BASE/vaults/prod/keys/<key-id> \\
  -H "Authorization: Bearer $CU_TOKEN" -H "Content-Type: application/json" \\
  -d '{"tags":["updated-by-cryptouser"]}'`,
        expected: "200",
        assert: "200 — update is in the bundle",
      },
      {
        id: "F4",
        title: "All three rotation-policy methods are denied",
        surface: "http",
        gate: "vault-role",
        command: `for M in GET PUT DELETE; do
  curl -s -o /dev/null -w "$M %{http_code}\\n" -X $M \\
    $BASE/vaults/prod/keys/<key-id>/rotationpolicy \\
    -H "Authorization: Bearer $CU_TOKEN"
done`,
        expected: `GET 403
PUT 403
DELETE 403`,
        assert: "403 on all three verbs",
      },
      {
        id: "F5",
        title: "The contrast that proves these are real denials",
        surface: "http",
        gate: "none",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' \\
  $BASE/vaults/prod/keys/<key-id>/rotationpolicy \\
  -H "Authorization: Bearer $ADMIN_TOKEN"`,
        expected: "404 rotation policy not found — a genuine “nothing set yet”",
        assert: "404, not 403 — same route, different principal",
        flag: "divergence",
        notes:
          "Commit `cdd591c` added the rotation-policy actions to Crypto Officer and Administrator only, stating *“not Crypto User, matching Azure.”* The exclusion is deliberate.",
      },
    ],
  },
]
