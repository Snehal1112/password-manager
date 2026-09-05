import type { Suite } from "./types"

export const journeysNU: Suite[] = [
  {
    key: "N",
    title: "Multi-vault isolation verification",
    actor: "alice and bob — one vault each",
    premise:
      "Cross-vault access must be a 403 deny-by-default, never a 404 and never a partial leak. The cache check at the end is a security assertion, not a performance one.",
    cases: [
      {
        id: "N1",
        title: "Two users, one vault each",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant alice --role "Key Vault Secrets Officer" --vault vault-a
rocketvault vault-access grant bob   --role "Key Vault Secrets Officer" --vault vault-b`,
        expected: "Two assignments in two vaults.",
        assert: "Neither principal holds anything in the other's vault",
      },
      {
        id: "N2",
        title: "Alice cannot reach vault-b's secret by exact UUID",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault secrets get <vault-b-secret-id> --vault vault-b`,
        expected: "Error: forbidden: no role grants ... in this vault",
        assert: "Denied even with the exact id in hand",
      },
      {
        id: "N3",
        title: "403, not 404, and not a silent success",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' $BASE/vaults/vault-b/secrets/<id> \\
  -H "Authorization: Bearer $ALICE_TOKEN"`,
        expected: "403 — not a silent success, not a partial leak",
        assert: "Exactly 403",
        notes:
          "v1 of this document claimed 404. It is 403 deny-by-default. Retract any test asserting 404.",
      },
      {
        id: "N4",
        title: "The default vault cannot be deleted",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults delete default`,
        expected: "Error: the default vault cannot be deleted",
        assert: "Refused — otherwise `default` behaves like any named vault",
      },
      {
        id: "N5",
        title:
          "A stale vault cache must not produce a wrong authorization answer",
        surface: "http",
        gate: "vault-role",
        precondition: "cache.vaults.enabled: true, inside a live TTL window.",
        command: `curl -s -X PATCH $BASE/vaults/vault-a \\
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \\
  -d '{"enabled":false}'

# Immediately resolve the same vault by name through a different path:
curl -s -o /dev/null -w '%{http_code}\\n' $BASE/vaults/vault-a/secrets \\
  -H "Authorization: Bearer $ALICE_TOKEN"`,
        expected:
          "The answer must reflect the vault being disabled, not a stale cached record.",
        assert: "No incorrect authorization decision from a cached vault",
        flag: "trap",
        notes:
          "`vaultcache` sits directly in the authorization path — `VaultResolutionMiddleware` reads it on nearly every request. This is a security check that happens to look like a cache check.",
      },
    ],
  },
  {
    key: "O",
    title: "Migrating a secret set to a new vault",
    actor: "Marcus — secrets_manager",
    premise:
      "Export, import, and the three ways the passphrase can be wrong. Two named traps: `generate-password` is not the HTTP generate route, and `--format` describes the payload inside the envelope, not the file on disk.",
    cases: [
      {
        id: "O1",
        title: "Provision the new vault and mirror the role",
        surface: "cli",
        gate: "management",
        command: `rocketvault vaults create payments

rocketvault vault-access grant priya  --role "Key Vault Administrator" --vault payments
rocketvault vault-access grant marcus --role "Key Vault Secrets Officer" --vault payments`,
        expected: "The vault exists and both principals hold a role in it.",
        assert: "Priya must self-grant here too (see A7)",
      },
      {
        id: "O2",
        title: "generate-password runs entirely locally",
        surface: "local",
        gate: "none",
        command: `GENERATED_PW=$(rocketvault secrets generate-password --length 24 --special=true \\
  | awk '{print $NF}')`,
        expected: "Generated password: <24 random chars>",
        assert: "No login, no vault, nothing stored",
      },
      {
        id: "O3",
        title: "generate-password is NOT the HTTP generate route",
        surface: "both",
        gate: "none",
        command: `# CLI:  prints a string, never touches a vault
# HTTP: POST /vaults/{name}/secrets/generate takes a name and creates
#       the secret in one step, storing the value`,
        expected:
          "Two different operations that share a name. Neither surface has the other's behaviour.",
        assert: "No CLI command does what the HTTP route does, and vice versa",
        flag: "divergence",
      },
      {
        id: "O4",
        title: "Create a secret from the generated value",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault secrets create payments-db-pass "$GENERATED_PW" --tags prod,db --vault payments`,
        expected: "The secret is created.",
        assert: "Succeeds — Marcus holds secrets_manager globally",
      },
      {
        id: "O5",
        title: "Export is encrypted by default",
        surface: "cli",
        gate: "global-role",
        command: `export ROCKETVAULT_EXPORT_PASSPHRASE='correct-horse-battery-staple'

rocketvault secrets export --file /tmp/payments-legacy.json \\
  --tags payments-legacy --vault dev`,
        expected: `Secrets exported successfully
Format: json
Encryption: passphrase (argon2id + AES-256-GCM)
File: /tmp/payments-legacy.json`,
        assert: "Encryption line reads argon2id + AES-256-GCM",
      },
      {
        id: "O6",
        title: "Import with no passphrase available names the fix",
        surface: "cli",
        gate: "validation",
        command: `unset ROCKETVAULT_EXPORT_PASSPHRASE

rocketvault secrets import --file /tmp/payments-legacy.json --vault payments`,
        expected: `Error: /tmp/payments-legacy.json is an encrypted export but no passphrase
is available: pass --passphrase-file or set ROCKETVAULT_EXPORT_PASSPHRASE`,
        assert: "The error names both ways to supply it",
      },
      {
        id: "O7",
        title: "A wrong passphrase fails differently from a missing one",
        surface: "cli",
        gate: "validation",
        command: `echo 'not-the-real-passphrase' > /tmp/wrong-pass.txt
rocketvault secrets import --file /tmp/payments-legacy.json \\
  --passphrase-file /tmp/wrong-pass.txt --vault payments`,
        expected:
          "Error: failed to decrypt /tmp/payments-legacy.json: wrong passphrase or corrupted file",
        assert: "Distinct message — the file is real, the key does not open it",
        notes:
          "Three distinguishable failures across O6, O7 and a genuinely corrupt file. Assert on the message, not just the exit code.",
      },
      {
        id: "O8",
        title: "Correct passphrase, correct target vault",
        surface: "cli",
        gate: "global-role",
        command: `echo 'correct-horse-battery-staple' > /tmp/export-pass.txt
rocketvault secrets import --file /tmp/payments-legacy.json \\
  --passphrase-file /tmp/export-pass.txt --vault payments`,
        expected: `Secrets imported successfully
Imported: 6
Skipped: 0
Failed: 0`,
        assert: "6 imported, 0 skipped, 0 failed",
      },
      {
        id: "O9",
        title: "--format describes the payload, not the file on disk",
        surface: "cli",
        gate: "validation",
        command: `rocketvault secrets export --file /tmp/x.csv --format csv --vault dev
file /tmp/x.csv                       # reports JSON
rocketvault secrets import --file /tmp/x.csv --format csv --vault payments`,
        expected:
          "A sealed CSV export is a JSON envelope on disk, and is read back with --format csv.",
        assert: "--format csv on import, even though `file` says JSON",
        flag: "trap",
      },
      {
        id: "O10",
        title: "HTTP export and import have genuinely different shapes",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -X POST $BASE/vaults/dev/secrets/export \\
  -H "Authorization: Bearer $MARCUS_TOKEN" -H "Content-Type: application/json" \\
  -d '{"format":"json","tags":["payments-legacy"],"include_tags":true,
       "encrypt":true,"passphrase":"correct-horse-battery-staple"}' \\
  -o /tmp/payments-legacy-http.json

curl -s -X POST $BASE/vaults/payments/secrets/import \\
  -H "Authorization: Bearer $MARCUS_TOKEN" \\
  -F "file=@/tmp/payments-legacy-http.json" \\
  -F "format=json" -F "overwrite=false" \\
  -F "passphrase=correct-horse-battery-staple" | jq .`,
        expected: `{"success":true,"message":"Successfully imported 6/6 secrets", ...}`,
        assert: "Export is a JSON body returning bytes; import is multipart",
      },
      {
        id: "O11",
        title: "Retire the originals one UUID at a time",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault secrets delete <legacy-secret-id> --vault dev`,
        expected: "Soft-deleted. No confirmation prompt.",
        assert: "No --force, no batch form, no prompt",
        flag: "trap",
        notes:
          "Each of the six migrated secrets needs its own invocation. There is no “delete all matching tag”.",
      },
    ],
  },
  {
    key: "P",
    title: "A user-role principal runs the entire secret-rotation lifecycle",
    actor: "Wren — global role user, Key Vault Secrets Officer in prod",
    premise:
      "`secrets rotation *` is the one command tree with no CLI global-role gate and no HTTP route at all. The same principal is refused `secrets create` and permitted to rotate credentials on demand.",
    cases: [
      {
        id: "P1",
        title: "Grant Secrets Officer to a bare `user`",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-access grant wren --role "Key Vault Secrets Officer" --vault prod`,
        expected:
          "granted Key Vault Secrets Officer to wren in vault (assignment ...)",
        assert: "Granted",
      },
      {
        id: "P2",
        title: "secrets create is refused before the vault check runs",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault secrets create scratch-secret 'x' --vault prod`,
        expected: "Error: forbidden: requires admin or secrets_manager role",
        assert: "Denied at the global-role gate",
      },
      {
        id: "P3",
        title: "secrets rotation create is permitted for the same principal",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation create --name db-cred-30d --interval 30 \\
  --reminder 7 --auto-rotate --vault prod`,
        expected: `Rotation policy created successfully
Policy ID: <policy-id>
Name: db-cred-30d
Interval: 30 days
Auto-rotate: true`,
        assert: "Succeeds — no global role is checked on this tree",
        flag: "divergence",
        notes:
          "Same principal, same vault, same global role as P2. One command is forbidden before it looks at her vault grant; the other never asks the question. Whether that is an oversight or a scope decision is not documented anywhere as intentional.",
      },
      {
        id: "P4",
        title: "Assign the policy to a real secret",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation assign --policy-id <policy-id> \\
  --secret-id <secret-id> --vault prod`,
        expected: "Policy assigned to secret successfully.",
        assert: "Assigned",
      },
      {
        id: "P5",
        title: "Re-assigning the same pair leaks a triple-wrapped driver error",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation assign --policy-id <policy-id> --secret-id <secret-id> --vault prod`,
        expected: `Error: failed to assign policy to secret: failed to assign policy to secret: failed to
assign policy to secret: UNIQUE constraint failed: secret_policies.secret_id, secret_policies.policy_id`,
        assert: "Three layers of the same sentence around one constraint name",
        flag: "gap",
        notes:
          "The service wraps once, the CLI wraps again on top of `RunE`'s own `%w`. If you script this, match `UNIQUE constraint failed` rather than a clean message.",
      },
      {
        id: "P6",
        title: "List the rotation policies",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation list --vault prod`,
        expected: `ID           NAME         INTERVAL  AUTO-ROTATE  ENABLED  CREATED
<policy-id>  db-cred-30d  30 days   true         true     2026-08-25

Found 1 rotation policies`,
        assert: "One policy, auto-rotate true",
      },
      {
        id: "P7",
        title: "Check what is due rather than waiting to find out",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation status --vault prod`,
        expected: `Rotation Status
Secrets due for rotation:
  - Secret <secret-id-abbrev>... (next: 2026-09-24)

Active rotation policies:
  - db-cred-30d: every 30 days (auto-rotate enabled)`,
        assert: "Due secrets and active policies both listed",
        notes:
          "Auto-rotate only fires from inside a live `serve` process, silently, on its own schedule.",
      },
      {
        id: "P8",
        title: "Manual rotation needs a value source",
        surface: "cli",
        gate: "validation",
        command: `rocketvault secrets rotation rotate --secret-id <secret-id> --policy-id <policy-id> --vault prod`,
        expected:
          "Error: no new value: pass --value <value> to set one, or --generate to have one generated",
        assert: "Refuses rather than generating one implicitly",
      },
      {
        id: "P9",
        title: "Rotate with a generated value",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation rotate --secret-id <secret-id> --policy-id <policy-id> \\
  --generate --length 24 --vault prod`,
        expected: "Secret rotated successfully.",
        assert: "Rotated",
      },
      {
        id: "P10",
        title: "TRIGGERED_BY always reads manual, even for scheduled rotations",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation history --secret-id <secret-id> --vault prod`,
        expected: `ROTATED_AT        TRIGGERED_BY  PREV_VERSION  NEW_VERSION  NOTES
2026-08-25 22:24  manual        1             2

Found 1 rotation events`,
        assert: "manual — and it will read manual for scheduler runs too",
        flag: "gap",
        notes:
          "`model.TriggerScheduled` exists in `model/rotation.go` and is never referenced. Both the CLI's manual rotate and the background scheduler funnel through `PerformManualRotation`, which hardcodes `TriggeredBy: model.TriggerManual`. The column does not distinguish rotation sources. Nothing outside RocketVault is told about the new value either way.",
      },
      {
        id: "P11",
        title: "rotation update is a partial update",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation update --id <policy-id> --auto-rotate=false --vault prod`,
        expected: "Rotation policy updated successfully.",
        assert: "Only the flags passed change",
        notes:
          "Contrast with `keys rotation-policy set` (C14), which is a full replace. Two rotation-policy surfaces, two contracts.",
      },
      {
        id: "P12",
        title: "Unassign twice: the second time errors",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation unassign --policy-id <policy-id> --secret-id <secret-id> --vault prod
rocketvault secrets rotation unassign --policy-id <policy-id> --secret-id <secret-id> --vault prod`,
        expected: `Policy removed from secret successfully.
Error: failed to remove policy from secret: failed to remove policy from secret: policy assignment not found`,
        assert: "First succeeds, second errors",
      },
      {
        id: "P13",
        title: "Delete twice: the second time errors",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation delete --id <policy-id> --vault prod
rocketvault secrets rotation delete --id <policy-id> --vault prod`,
        expected: `Rotation policy deleted successfully.
Error: failed to delete rotation policy: failed to delete rotation policy: rotation policy not found`,
        assert: "First succeeds, second errors",
      },
      {
        id: "P14",
        title: "History outlives the policy that caused it",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets rotation history --secret-id <secret-id> --vault prod`,
        expected:
          "The manual entry is still there, now with a PolicyID that no longer resolves.",
        assert: "Past events survive; by design",
      },
      {
        id: "P15",
        title: "No HTTP route exists — 404, not 403",
        surface: "http",
        gate: "none",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' $BASE/vaults/prod/secrets/rotation-policies \\
  -H "Authorization: Bearer $WREN_TOKEN"
curl -s -o /dev/null -w '%{http_code}\\n' $BASE/secrets/rotation \\
  -H "Authorization: Bearer $WREN_TOKEN"`,
        expected: `404
404`,
        assert: "404 on both — there is no authorization decision to make",
        flag: "gap",
      },
    ],
  },
  {
    key: "Q",
    title: "Certificate manager issues, chains and retires a TLS certificate",
    actor: "Noor — certificate_manager",
    premise:
      "A certificate is always issued over an existing key, and key creation needs a role Noor does not hold. The divergence to catch: `renew` checks `certificates/create`, not `certificates/update`, unlike every other mutating cert command.",
    cases: [
      {
        id: "Q1",
        title: "Create the account with the required global role",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault users create --new-username noor --new-password '<pw>' --new-role certificate_manager

rocketvault vault-access grant noor --role "Key Vault Certificates Officer" --vault prod`,
        expected: "The user exists and holds Certificates Officer in prod.",
        assert:
          "Certificates Officer is full control, and is one of Wren's eight",
      },
      {
        id: "Q2",
        title: "certificate_manager does not cover key creation",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault keys create --name checkout-tls-leaf --type RSA --bits 2048 --vault prod`,
        expected: "Error: forbidden: requires admin or crypto_manager role",
        assert: "She cannot self-serve the key her certificate needs",
      },
      {
        id: "Q3",
        title: "Sofia creates the two keys the journey needs",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault keys create --name checkout-ca-key --type RSA --bits 4096 --vault prod
rocketvault keys create --name checkout-tls-leaf --type ECDSA --curve P-384 --vault prod`,
        expected: "Two keys.",
        assert: "Created by crypto_manager, consumed by certificate_manager",
      },
      {
        id: "Q4",
        title: "Self-signed certificate over an existing key",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault certificates create --name checkout-tls-selfsigned \\
  --key-id <checkout-tls-leaf-key-id> --validity-days 365 --tags prod,tls --vault prod`,
        expected: `ID    Name                       Created
<id>  checkout-tls-selfsigned    2026-08-25T...`,
        assert: "Created",
      },
      {
        id: "Q5",
        title: "Flag validation runs before authorization or key lookup",
        surface: "cli",
        gate: "validation",
        command: `rocketvault certificates create --key-id <checkout-tls-leaf-key-id> --validity-days 365 --vault prod`,
        expected: "Error: name, key-id, and validity-days are required",
        assert: "Rejected on the missing name, before any auth check",
      },
      {
        id: "Q6",
        title: "Stand up a CA, then issue a leaf against it",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault certificates create --name checkout-root-ca \\
  --key-id <checkout-ca-key-id> --is-ca --validity-days 3650 --vault prod

rocketvault certificates create --name checkout-tls-chained \\
  --key-id <checkout-tls-leaf-key-id> --ca-cert-id <ca-cert-id> \\
  --validity-days 90 --tags prod,tls --auto-renew --renewal-days 30 --vault prod`,
        expected: "A CA certificate, then a leaf signed by it.",
        assert: "Both created; the leaf chains to the CA",
      },
      {
        id: "Q7",
        title: "--is-ca and --ca-cert-id are mutually exclusive",
        surface: "cli",
        gate: "validation",
        command: `rocketvault certificates create --name broken --key-id <checkout-tls-leaf-key-id> \\
  --is-ca --ca-cert-id <ca-cert-id> --validity-days 90 --vault prod`,
        expected:
          "Error: failed to create certificate: cannot issue a CA-signed certificate as a CA: intermediate CA certificates are not supported",
        assert: "Refused — a cert is either the CA or signed by one",
      },
      {
        id: "Q8",
        title: "--auto-renew only arms the scheduler",
        surface: "cli",
        gate: "none",
        command: `# Confirm the scheduler ran. Do not expect a notification.`,
        expected: "No notification of any kind is delivered.",
        assert: "Journey C's finding holds for certificates too",
        flag: "gap",
      },
      {
        id: "Q9",
        title: "certificate is an alias for certificates everywhere",
        surface: "cli",
        gate: "none",
        command: `rocketvault certificate list --vault prod --output json
rocketvault certificate get <ca-cert-id> --vault prod`,
        expected: `ID    Name              Tags  Expires        AutoRenew  Created
<id>  checkout-root-ca        2036-08-23...  false      2026-08-25T...`,
        assert: "Singular and plural both work",
      },
      {
        id: "Q10",
        title: "Reads need no global role",
        surface: "cli",
        gate: "vault-role",
        precondition: "Run as daeho, holding only Key Vault Reader in prod.",
        command: `rocketvault certificate list --vault prod`,
        expected: "The listing renders.",
        assert: "Works without certificate_manager",
      },
      {
        id: "Q11",
        title: "Update is metadata only and never re-signs",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault certificate update <leaf-cert-id> --tags prod,tls,rotated-2026-08 --vault prod
rocketvault certificate get <leaf-cert-id> --vault prod --output json | jq .name`,
        expected: "Certificate updated successfully. The name is unchanged.",
        assert: "Only the flags passed take effect",
      },
      {
        id: "Q12",
        title: "Renew re-issues in place over the same key and id",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault certificate renew <leaf-cert-id> --validity-days 180 --vault prod`,
        expected: `Certificate renewed successfully!
Certificate ID: <leaf-cert-id>
Validity: 180 days`,
        assert: "Same id, same key, new validity",
      },
      {
        id: "Q13",
        title: "Renew checks certificates/create, not certificates/update",
        surface: "cli",
        gate: "vault-role",
        precondition: `rocketvault vault-access grant noor --role "Key Vault Certificate User" --vault staging`,
        command: `rocketvault certificate renew <staging-cert-id> --vault staging`,
        expected:
          "Error: failed to renew certificate: forbidden: no role grants Microsoft.KeyVault/vaults/certificates/create in this vault",
        assert: "The action named in the error is create, not update",
        flag: "divergence",
        notes:
          "Unlike every other mutating cert command. A principal with update but not create can run `certificate update` and not `certificate renew`.",
      },
      {
        id: "Q14",
        title: "An expired or disabled CA blocks renewal of what it signed",
        surface: "cli",
        gate: "none",
        command: `rocketvault certificate renew <leaf-signed-by-expired-ca> --vault prod`,
        expected: "Refused — never silently downgraded to self-signed.",
        assert: "Refusal, not a silent self-signed fallback",
      },
      {
        id: "Q15",
        title: "Delete is soft-delete, and the row survives",
        surface: "cli",
        gate: "global-role",
        command: `rocketvault certificate delete <leaf-cert-id> --vault prod
rocketvault certificate list --vault prod --output json | jq '[.[] | select(.id=="<leaf-cert-id>")]'
rocketvault certificate get <leaf-cert-id> --vault prod`,
        expected: `Certificate deleted successfully: <leaf-cert-id>
[]
Error: failed to get certificate: certificate not found: certificate not found or access denied`,
        assert: "Gone from listing and get; still a soft-deleted row",
      },
      {
        id: "Q16",
        title: "Recovery needs REST — the CLI has no subcommand",
        surface: "http",
        gate: "vault-role",
        command: `curl -s -X POST $BASE/vaults/prod/deleted/certificates/<leaf-cert-id>/restore \\
  -H "Authorization: Bearer $NOOR_OR_ADMIN_TOKEN"`,
        expected: "The certificate is restored.",
        assert: "REST-only, mirroring the key-lifecycle gaps",
        flag: "gap",
      },
    ],
  },
  {
    key: "R",
    title: "Disaster recovery: scheduled backups and a post-rotation restore",
    actor: "Priya — admin only, with no vault scoping at all",
    premise:
      "A backup is one whole-instance JSON file. The trap is that a backup taken before a master-key rotation cannot be restored after it, because both the file wrapper and the column ciphertext are sealed with the same key.",
    cases: [
      {
        id: "R1",
        title: "backup is a pure global-admin gate with no vault lookup",
        surface: "cli",
        gate: "global-admin",
        precondition: "Run as marcus, holding secrets_manager.",
        command: `rocketvault backup list --dir /var/backups/rocketvault`,
        expected: "Error: forbidden: requires admin role",
        assert: "Denied — --vault is accepted but never read",
        notes:
          "`requireBackupAdmin` checks only the admin role. An operator with a role in one vault cannot use these commands regardless of what they pass to `--vault`.",
      },
      {
        id: "R2",
        title: "Create a backup by hand before trusting cron",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault backup create --file /var/backups/rocketvault/nightly-2026-08-25.backup`,
        expected: `Backup created successfully.
File: /var/backups/rocketvault/nightly-2026-08-25.backup
Encrypted: true`,
        assert: "Encrypted: true — this line is your real confirmation",
      },
      {
        id: "R3",
        title: "The destination flag is --file, not --output",
        surface: "cli",
        gate: "validation",
        command: `rocketvault backup create --output /var/backups/x.backup`,
        expected:
          "Treated as root's persistent --output format selector, and rejected as an invalid format.",
        assert: "--output is the table/json/yaml selector, not a path",
        flag: "trap",
        notes:
          "`backup create` briefly had its own local `--output` for the file path, which collided with root's. Renamed to `--file`/`-f` on 2026-08-22 (§ B48).",
      },
      {
        id: "R4",
        title: "backup list shows dashes for encrypted backups",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault backup list --dir /var/backups/rocketvault`,
        expected: `TIMESTAMP  VERSION  TABLES  RECORDS  ENCRYPTED  FILE                        SIZE    MODIFIED
-          -        -       -        true       nightly-2026-08-25.backup   482113  2026-08-25 02:00:01

Found 1 backup files in /var/backups/rocketvault`,
        assert: "The dashes are correct, not broken",
        notes:
          "`backup list` never touches the master key, so it cannot parse an encrypted file for counts. Only filename, size and mtime come from the filesystem. It is for inventory, not verification.",
      },
      {
        id: "R5",
        title: "There is no built-in scheduler",
        surface: "local",
        gate: "none",
        command: `# /etc/cron.d/rocketvault-backup
0 2 * * * root cd /opt/rocketvault && ./rocketvault backup create \\
  --file /var/backups/rocketvault/nightly-$(date +\\%F).backup \\
  >> /var/log/rv-backup.log 2>&1`,
        expected:
          "No --schedule flag, no daemon. “Scheduled” means an external cron or systemd timer.",
        assert: "The cached session refreshes itself, so cron keeps working",
        flag: "gap",
      },
      {
        id: "R6",
        title: "Restoring across a master-key rotation fails on the auth tag",
        surface: "cli",
        gate: "global-admin",
        precondition:
          "The backup was taken before `master-key rotate` ran; config now holds the new key.",
        command: `rocketvault backup restore --file /var/backups/rocketvault/nightly-2026-08-25.backup`,
        expected: `Error: restore failed: failed to read backup file: failed to decrypt backup: failed to decrypt: cipher: message authentication failed`,
        assert: "GCM auth-tag failure",
        flag: "trap",
        notes:
          "Both column encryption and the backup file's own `--encrypt` wrapper use the same `master_key`. `master-key rotate` re-encrypts every live row and leaves backup files sealed under the old key.",
      },
      {
        id: "R7",
        title: "The restore succeeds under the pre-rotation key",
        surface: "cli",
        gate: "global-admin",
        command: `export MASTER_KEY="<the pre-rotation key, saved before the rotation>"

rocketvault backup restore --file /var/backups/rocketvault/nightly-2026-08-25.backup`,
        expected: `Are you sure you want to continue? (type 'yes' to confirm): yes
Database restored successfully from /var/backups/rocketvault/nightly-2026-08-25.backup`,
        assert: "Restores once pointed at the right key",
        notes:
          "Losing the pre-rotation key permanently is unrecoverable: every restored secret, key PEM and certificate private key is column-level ciphertext under it.",
      },
      {
        id: "R8",
        title: "The restore does not undo the rotation",
        surface: "cli",
        gate: "none",
        command: `# Decide deliberately: re-run master-key rotate onto the new key,
# or leave the config on the old key.`,
        expected:
          "The restored rows are sealed under the old key while MASTER_KEY still points at it.",
        assert: "A deliberate decision is required before restarting",
        flag: "trap",
      },
      {
        id: "R9",
        title: "Restore only refills tables present in the file",
        surface: "cli",
        gate: "none",
        command: `# A table added by a migration after the backup was taken is untouched.`,
        expected: "Tables the backup does not contain are left alone.",
        assert: "Restoring old data does not roll back the schema",
      },
      {
        id: "R10",
        title: "Sessions are wiped and refilled like every other table",
        surface: "cli",
        gate: "none",
        command: `sudo systemctl start rocketvault
# Have everyone re-run "rocketvault users login".`,
        expected:
          "Server-side session state created after the backup point is gone.",
        assert: "Everyone must log in again",
      },
      {
        id: "R11",
        title: "Restore has no dry-run and no selective mode",
        surface: "cli",
        gate: "none",
        command: `rocketvault backup restore --dry-run --file <backup>`,
        expected:
          "No such flag. It is whole-file, whole-transaction, or nothing.",
        assert: "No dry-run, no partial restore",
        flag: "gap",
        notes:
          "A backup is whole-instance: every vault, every table verbatim, including soft-deleted rows, users, role assignments, sessions and the audit log. The inherited `--vault` flag is accepted but ignored.",
      },
    ],
  },
  {
    key: "S",
    title: "Rotating the master key after an infrastructure departure",
    actor: "Priya — admin only; crypto_manager and secrets_manager get no pass",
    premise:
      "Revoking role assignments does nothing about a key someone copied off the host. This is the only remedy — and it is not atomic, not enforced offline, and does not write the new key back to your config.",
    cases: [
      {
        id: "S1",
        title: "Non-admins cannot even dry-run it",
        surface: "cli",
        gate: "global-admin",
        precondition: "Run as daeho, global role user.",
        command: `rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --dry-run`,
        expected: "Error: forbidden: requires admin role",
        assert: "Denied at --dry-run, before anything is read",
      },
      {
        id: "S2",
        title: "A stray exported MASTER_KEY silently becomes the old key",
        surface: "cli",
        gate: "validation",
        precondition:
          "Export both MASTER_KEY and NEW_MASTER_KEY to the same value.",
        command: `rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --dry-run`,
        expected: `Error: the new master key is identical to the old one (old key source: config file
(master_key)); note that an exported MASTER_KEY environment variable takes
precedence over the config file`,
        assert:
          "The label says “config file” even when the env var supplied it",
        flag: "trap",
        notes:
          "Viper resolves an exported `MASTER_KEY` before the config file, so `--old-key-env` left unset picks up the leftover value. The error's own source label is misleading here — read the second clause.",
      },
      {
        id: "S3",
        title: "Nothing stops you running this against a live server",
        surface: "cli",
        gate: "none",
        command: `# The --help text and the runbook both say to stop the server.
# runMasterKeyRotate never checks for a running process, lock or PID file.`,
        expected: "It runs. The guard is narrower and comes later — see S4.",
        assert: "Server-stopped is advisory, not enforced",
        flag: "gap",
      },
      {
        id: "S4",
        title: "A row rewritten mid-run aborts its batch",
        surface: "cli",
        gate: "none",
        command: `# Every UPDATE is qualified with AND <column> = ? bound to the ciphertext
# read during the plan pass.`,
        expected: `Error: master key rotation failed: keys.value: row [<id>] changed while the rotation
was running (0 rows updated, expected 1) — stop the RocketVault server and re-run`,
        assert: "Aborts rather than clobbering a concurrent write",
        notes:
          "The realistic outcome of running this live is a **partially rotated instance** — `secrets` done, `keys` half-done — not corruption. Targets are processed one table at a time and batches commit independently.",
      },
      {
        id: "S5",
        title: "Back up first — there is no inverse command",
        surface: "local",
        gate: "none",
        command: `cp dev-rocketvault.db dev-rocketvault.db.pre-rotation-2026-08-25   # SQLite
# pg_dump "$DATABASE_URL" > rocketvault-pre-rotation.sql           # Postgres`,
        expected: "A copy on disk.",
        assert: "This plus the still-valid old key is the only rollback path",
      },
      {
        id: "S6",
        title: "Read the dry-run report before touching anything",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --dry-run`,
        expected: `Old master key source: config file (master_key)
New master key source: environment variable NEW_MASTER_KEY
Mode: DRY RUN (no rows will be written)

TABLE            COLUMN       ROWS  RE-ENCRYPTED  ALREADY NEW KEY  SKIPPED (HSM)
secrets          value        3     3             0                0
secret_versions  value        0     0             0                0
keys             value        1     0             0                1
key_versions     value        0     0             0                0
certificates     private_key  0     0             0                0

Total rows re-encrypted: 3

Dry run complete. No rows were modified.`,
        assert: "Row counts match what you expect to be in the instance",
      },
      {
        id: "S7",
        title: "HSM-backed keys are skipped and not covered by this rotation",
        surface: "cli",
        gate: "none",
        command: `# SKIPPED (HSM) counts key rows whose value is a pkcs11: token label
# rather than sealed PEM.`,
        expected:
          "Those rows are untouched, because the material never left the HSM.",
        assert: "HSM key exposure is a separate PKCS#11/PIN problem",
      },
      {
        id: "S8",
        title: "Anything but the exact string yes aborts — and exits 0",
        surface: "cli",
        gate: "validation",
        command: `echo "" | rocketvault master-key rotate --new-key-env NEW_MASTER_KEY
echo $?`,
        expected: `Aborted.
0`,
        assert: "Exit code 0 on an aborted, no-op rotation",
        flag: "trap",
        notes:
          "A maintenance script checking only the exit code reads this as success. For unattended runs pass `--yes` rather than piping an answer.",
      },
      {
        id: "S9",
        title: "Run it for real",
        surface: "cli",
        gate: "global-admin",
        command: `rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --yes`,
        expected: `Rotation complete. Set the new key as master_key in the configuration (or as the
MASTER_KEY environment variable) and restart the server.
Reminder: existing database backup files were sealed under the old key and are not
affected by this rotation — they will not restore once the old key is retired.`,
        assert: "Same counts as the dry run",
      },
      {
        id: "S10",
        title: "Re-running with the same key pair is safe",
        surface: "cli",
        gate: "none",
        command: `rocketvault master-key rotate --new-key-env NEW_MASTER_KEY --yes`,
        expected:
          "Rows already on the new key are counted under ALREADY NEW KEY and skipped.",
        assert: "Safe to resume — which is not the same as atomic",
      },
      {
        id: "S11",
        title: "The new key is never written back to the config",
        surface: "local",
        gate: "none",
        command: `# .rocketvault.yaml
master_key: "<value of $NEW_MASTER_KEY>"`,
        expected: "You edit this by hand, always.",
        assert: "Manual edit required",
        flag: "gap",
      },
      {
        id: "S12",
        title: "Verify with a command that actually decrypts",
        surface: "cli",
        gate: "vault-role",
        command: `rocketvault serve
rocketvault secrets list --vault default`,
        expected: "A clean read, which proves config and database agree.",
        assert: "Use secrets list, not certificates list",
        flag: "trap",
        notes:
          "`ListCertificates`/`GetCertificate` never touch `private_key`, so a clean `certificates list` proves nothing about the rotation.",
      },
    ],
  },
  {
    key: "T",
    title: "Working across prod, staging and dev from one laptop",
    actor: "Priya — three separate RocketVault deployments",
    premise:
      "A context is the lowest-precedence, easiest-to-forget source of a target, which is exactly why it causes surprises days after it was set. Most command groups fail closed; `secrets` does not.",
    cases: [
      {
        id: "T1",
        title: "Add three contexts; only --server is required",
        surface: "local",
        gate: "none",
        command: `rocketvault context add prod \\
  --server https://vault.prod.internal \\
  --default-username ops-oncall --default-vault prod

rocketvault context add staging --server https://vault.staging.internal:8443 --default-vault staging
rocketvault context add dev --server http://localhost:8774 --default-vault dev

rocketvault context list`,
        expected: `Name     Server                               Default Username  Default Vault  Current
dev      http://localhost:8774                                  dev
prod     https://vault.prod.internal          ops-oncall        prod
staging  https://vault.staging.internal:8443                    staging`,
        assert: "Three rows; no Current marked yet",
        notes:
          "`context add` writes only to `~/.rocketvault/contexts.json`. It never dials the server and stores no credentials, so an environment that is down still saves cleanly.",
      },
      {
        id: "T2",
        title: "A missing URL scheme is caught at save time",
        surface: "local",
        gate: "validation",
        command: `rocketvault context add prod --server vault.prod.internal`,
        expected: `Error: --server "vault.prod.internal" needs an http:// or https:// scheme (got "")`,
        assert: "Rejected here, not later as an opaque transport error",
      },
      {
        id: "T3",
        title: "Switch and confirm the active context",
        surface: "local",
        gate: "none",
        command: `rocketvault context use prod
rocketvault context current`,
        expected: "prod -> https://vault.prod.internal",
        assert: "Current reports prod",
      },
      {
        id: "T4",
        title: "Most command groups fail closed with a loud error",
        surface: "cli",
        gate: "none",
        precondition: "The prod context is active.",
        command: `rocketvault keys list --vault dev`,
        expected: `Error: remote mode (--server/ROCKETVAULT_ADDR/context "https://vault.prod.internal") is not yet supported for "rocketvault keys list"; unset it to run against the local instance`,
        assert: "Refused rather than guessing which instance was meant",
        notes:
          "The authority on what is remote-capable is the `remoteCapableCommands` map in `cmd/root.go` — read that, not a list in a document. As of 2026-09-04 it held `secrets` (all seven subcommands) and `users` (`login`, `logout`); `vault-access` (`grant`, `list`, `revoke`) has since joined them.",
      },
      {
        id: "T5",
        title: "A remote-capable group has no such guard",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets delete <secret-id>`,
        expected: `Error: remote authentication failed - no cached session for server https://vault.prod.internal; run 'rocketvault users login' or pass --username/--password/--totp-code or --client-id/--client-secret`,
        assert: "It tried the remote server rather than refusing",
      },
      {
        id: "T6",
        title: "A remote login becomes the default for later bare commands",
        surface: "cli",
        gate: "none",
        command: `rocketvault users login --username ops-oncall --password '<prod-password>' --totp-code 482913`,
        expected: "Login successful as ops-oncall.",
        assert: "Nothing in the output says it also became the current session",
        flag: "trap",
        notes:
          "The session is keyed per server (`srv_https_vault.prod.internal__ops-oncall.json`) inside the same `~/.rocketvault/sessions/` directory, but the “current session” pointer is a single global file shared between local and remote mode.",
      },
      {
        id: "T7",
        title: "The next morning: a bare command hits production",
        surface: "cli",
        gate: "none",
        command: `# No --server, no --username, no confirmation prompt.
rocketvault secrets delete <secret-id>`,
        expected: `time="…" level=info msg="Authenticated against remote server" command="Delete a secret by ID" server="https://vault.prod.internal" user=ops-oncall
Secret deleted successfully.`,
        assert:
          "server=… is printed twice on stderr — easy to miss, not silent",
        flag: "trap",
        notes:
          "The cached session is reused with no server-side revalidation; the CLI checks only the local `expires_at`. **Practical rule**: run `rocketvault context current` before any `secrets create/update/delete/import` you intend to be local, and do not discard stderr.",
      },
      {
        id: "T8",
        title: "An omitted --vault falls back to the context default",
        surface: "cli",
        gate: "none",
        command: `rocketvault secrets delete <secret-id>   # prod context active, no --vault`,
        expected:
          "Targets the context's --default-vault (prod), rather than erroring.",
        assert: "Falls back rather than refusing",
      },
      {
        id: "T9",
        title: "logout is scoped to the active target",
        surface: "cli",
        gate: "none",
        command: `rocketvault users logout`,
        expected: "Logged out ops-oncall.",
        assert: "Deletes the remote session file; the local one survives",
        notes:
          "With no `--username` it follows the current-session pointer, but only if that pointer belongs to this server; otherwise it reports `No cached session to log out of.` Client-side only — the JWT stays valid until it expires.",
      },
      {
        id: "T10",
        title: "Service-account credentials skip the session cache entirely",
        surface: "cli",
        gate: "none",
        command: `export ROCKETVAULT_CLIENT_ID=<client-id>
export ROCKETVAULT_CLIENT_SECRET=<client-secret>
rocketvault secrets list --vault prod`,
        expected: "Authenticates via the OAuth2 client-credentials grant.",
        assert: "Nothing written to ~/.rocketvault/sessions/",
        notes:
          "These take precedence over every other tier — over `--username/--password` and over any cached session.",
      },
      {
        id: "T11",
        title: "Half a credential pair is a usage error",
        surface: "cli",
        gate: "validation",
        command: `ROCKETVAULT_CLIENT_ID=<client-id> rocketvault secrets list`,
        expected: `Error: remote authentication failed - --client-id given without --client-secret (or ROCKETVAULT_CLIENT_SECRET)`,
        assert: "No silent fallback to an interactive session",
      },
      {
        id: "T12",
        title: "localhost does not get you back into local mode",
        surface: "cli",
        gate: "none",
        command: `rocketvault context use dev
rocketvault keys list --vault dev`,
        expected: `Error: remote mode (--server/ROCKETVAULT_ADDR/context "http://localhost:8774")
       is not yet supported for "rocketvault keys list"; unset it to run
       against the local instance`,
        assert: "The guard does not special-case loopback",
        flag: "trap",
      },
      {
        id: "T13",
        title: "context unset clears the pointer, keeping the saved entries",
        surface: "local",
        gate: "none",
        command: `rocketvault context unset
rocketvault keys list --vault dev`,
        expected: "Works again — no context, no --server, no ROCKETVAULT_ADDR.",
        assert: "Local mode restored; prod/staging/dev still saved",
      },
      {
        id: "T14",
        title: "context remove deletes the entry outright",
        surface: "local",
        gate: "none",
        command: `rocketvault context remove staging
rocketvault context list`,
        expected:
          "staging is gone. Had it been current, `current` now reports local mode.",
        assert: "A removed context cannot be left dangling as current",
      },
      {
        id: "T15",
        title: "An explicit --server always wins",
        surface: "cli",
        gate: "none",
        command: `rocketvault context use prod
rocketvault secrets list --server https://vault.staging.internal:8443`,
        expected: "Targets staging, not prod.",
        assert: "Precedence: --server, then ROCKETVAULT_ADDR, then the context",
      },
      {
        id: "T16",
        title:
          "grant, list and revoke now work remotely, byte-identical to local",
        surface: "cli",
        gate: "none",
        precondition:
          "The prod context is active and authenticated as ops-oncall (see T6).",
        command: `rocketvault vault-access grant daeho --role "Key Vault Reader" --vault prod
rocketvault vault-access list --vault prod
rocketvault vault-access revoke <assignment-id> --vault prod`,
        expected: `granted Key Vault Reader to daeho in vault (assignment <assignment-id>)
ASSIGNMENT-ID                         ROLE                 PRINCIPAL-ID
<assignment-id>                       Key Vault Reader     <daeho-user-id>
revoked assignment <assignment-id>`,
        assert: "Same output as local mode — no separate remote formatter",
        notes:
          "Local and remote print through the same `Fprintf` format strings in `cmd/vault-access/{grant,list,revoke}.go`.",
      },
      {
        id: "T17",
        title:
          "A remote denial surfaces the same message as local for all three",
        surface: "cli",
        gate: "vault-role",
        precondition:
          "The prod context is active and authenticated as a principal with no role assignment in the vault.",
        command: `rocketvault vault-access grant daeho --role "Key Vault Reader" --vault prod`,
        expected: `Error: failed to grant a role: no role assignment in this vault grants the required action`,
        assert:
          "Same denial text locally and remotely, for grant, list and revoke",
        notes:
          "Substitute `list role assignments` or `revoke a role assignment` for the other two — `cliclient.CLIError` wraps whichever operation name the adapter passed, but the wrapping and the underlying message are identical either way.",
      },
      {
        id: "T18",
        title: "vault-access roles stays local-only regardless of context",
        surface: "cli",
        gate: "none",
        precondition: "The prod context is active.",
        command: `rocketvault vault-access roles`,
        expected:
          "Prints the compiled-in role list; the active prod context has no effect.",
        assert: "An active context, local or remote, has no effect on it",
        notes:
          "`vault-access roles` did not join `remoteCapableCommands` — it is routed through `isLocalOnlyCommand` instead, because it only prints compiled-in role definitions and never contacts a server.",
      },
      {
        id: "T19",
        title:
          "ROCKETVAULT_VAULT diverges: vault-access honors it, secrets doesn't",
        surface: "cli",
        gate: "none",
        precondition:
          'The prod context is active (its default vault is "prod").',
        command: `export ROCKETVAULT_VAULT=payments

rocketvault vault-access list
rocketvault secrets list`,
        expected: `vault-access list acts on "payments" -- ResolveRemoteVault honors the env var.
secrets list acts on "prod" -- the secrets adapter never looks at ROCKETVAULT_VAULT and falls back to the context's default vault.`,
        assert: "Same shell, same context — two different vaults",
        flag: "trap",
        notes:
          "`vault-access grant/list/revoke` are the only three callers of `cliclient.ResolveRemoteVault`. The `secrets` remote adapters (`cmd/secrets/list.go:138-141` and its siblings) resolve `--vault` then `target.Vault` the older way, skipping `ROCKETVAULT_VAULT` entirely. Neither command errors and neither prints which vault it resolved to — reproducible and quiet.",
      },
      {
        id: "T20",
        title: "Only a --vault flag actually typed outranks ROCKETVAULT_VAULT",
        surface: "cli",
        gate: "none",
        precondition:
          "ROCKETVAULT_VAULT=payments exported, prod context active (see T19).",
        command: `rocketvault vault-access list --vault prod`,
        expected:
          'Acts on "prod" -- the flag was actually typed, so it outranks ROCKETVAULT_VAULT this time.',
        assert: "A typed flag wins; a non-empty default would not",
        flag: "trap",
        notes:
          '`ResolveRemoteVault` checks `cmd.Flags().Changed("vault")`, not whether the value is non-empty. A `--vault` left at a non-empty *default* is not a deliberate choice on the caller\'s part and would not outrank an exported `ROCKETVAULT_VAULT` — only a flag actually typed does.',
      },
    ],
  },
  {
    key: "U",
    title: "Wiring (and not relying on) a vault webhook",
    actor: "Priya — admin, authorized by CanManageVault",
    premise:
      "The config is real: it creates, encrypts and stores a webhook with a genuine signing secret. Nothing in RocketVault ever calls it. Configuring it today buys you nothing operationally.",
    cases: [
      {
        id: "U1",
        title: "Set a webhook and capture the show-once signing secret",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-webhook set --vault prod --url https://hooks.example/rocketvault`,
        expected: `Webhook configured for vault "prod":
  URL: https://hooks.example/rocketvault
  Enabled: true

  Signing Secret: XfUHEYSqLFk4IhYKn4Ilr3Q9EGMQGLKCpZWPgjB948c

Store the signing secret now — it is not retrievable after this.`,
        assert: "The secret is printed exactly once",
      },
      {
        id: "U2",
        title: "get never emits the signing secret",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-webhook get --vault prod`,
        expected: `Webhook for vault "prod":
  URL: https://hooks.example/rocketvault
  Enabled: true
  Created: 2026-08-25T...
  Updated: 2026-08-25T...`,
        assert: "No Signing Secret field, on this call or any other",
      },
      {
        id: "U3",
        title: "Plain HTTP URLs are rejected at set time",
        surface: "cli",
        gate: "validation",
        command: `rocketvault vault-webhook set --vault prod --url http://hooks.example/rocketvault`,
        expected:
          'Error: set webhook failed: webhook url must be an absolute https URL: got scheme "http"',
        assert: "Rejected on the scheme",
      },
      {
        id: "U4",
        title: "Embedded credentials are rejected without echoing them back",
        surface: "cli",
        gate: "validation",
        command: `rocketvault vault-webhook set --vault prod --url https://user:pass@hooks.example/rocketvault`,
        expected: `Error: set webhook failed: webhook url must be an absolute https URL: must not embed
credentials (user:password@); authenticate the receiver with this vault's webhook
signing secret instead`,
        assert: "The credential is not echoed into terminal history or logs",
      },
      {
        id: "U5",
        title: "This is the vault-management tier, not a data-plane role",
        surface: "cli",
        gate: "management",
        precondition:
          "Run as sofia, holding crypto_manager globally and Key Vault Crypto Officer in prod.",
        command: `rocketvault vault-webhook set --vault prod --url https://hooks.example/rocketvault`,
        expected: `Error: permission denied: managing webhook config for vault "prod" requires admin or vaults/manage`,
        assert: "Denied — holding Administrator in the vault is not enough",
      },
      {
        id: "U6",
        title: "The HTTP door gives the same answer",
        surface: "http",
        gate: "management",
        command: `curl -s -o /dev/null -w '%{http_code}\\n' -X PUT $BASE/vaults/prod/webhook \\
  -H "Authorization: Bearer $SOFIA_TOKEN" -H "Content-Type: application/json" \\
  -d '{"url":"https://hooks.example/rocketvault"}'`,
        expected: "403",
        assert: "No CLI/HTTP divergence here — both call CanManageVault",
        notes:
          "Unlike `vaults purge` (Journey K). `cmd/vault-webhook/authz.go` and `api/vault_webhook.go` call the identical `authz.CanManageVault`.",
      },
      {
        id: "U7",
        title: "signing_secret appears only when one is minted",
        surface: "http",
        gate: "management",
        command: `curl -s -X PUT $BASE/vaults/prod/webhook \\
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \\
  -d '{"url":"https://hooks.example/rocketvault","rotate_secret":false}' | jq .`,
        expected: `{"url":"...", "enabled":true, "created_at":"...", "updated_at":"..."}`,
        assert: "No signing_secret field on an update that did not rotate one",
      },
      {
        id: "U8",
        title: "delete is idempotent on both surfaces",
        surface: "cli",
        gate: "management",
        command: `rocketvault vault-webhook delete --vault prod
rocketvault vault-webhook delete --vault prod`,
        expected: `webhook configuration deleted for vault "prod"
webhook configuration deleted for vault "prod"`,
        assert: "Same message twice, not an error",
        notes:
          "Contrast with `keys rotation-policy delete` (C20), which does error the second time.",
      },
      {
        id: "U9",
        title: "Nothing ever sends",
        surface: "http",
        gate: "none",
        command: `# Point the URL at a request bin and exercise every rotation,
# expiry and reminder path in this playbook.`,
        expected:
          "Zero inbound requests. There is no sender, dispatcher or delivery worker.",
        assert: "No outbound HTTP call is ever made",
        flag: "gap",
        notes:
          "`docs/superpowers/specs/2026-08-20-webhook-delivery-primitive-design.md` is **Proposed**, not built. This is the same gap Journey C flags from the other side: `notify_before_expiry_days` is stored because there is nothing downstream a trigger could call. **Do not build an operational process that depends on this webhook firing.**",
      },
    ],
  },
]
