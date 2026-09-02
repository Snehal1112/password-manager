import {
  Activity,
  Ban,
  Boxes,
  Braces,
  Cpu,
  Database,
  DatabaseBackup,
  EyeOff,
  FileBadge,
  Gauge,
  Globe,
  HardDrive,
  KeyRound,
  Layers,
  Lock,
  LogIn,
  Plug,
  Power,
  RotateCcw,
  ScrollText,
  Terminal,
  Workflow,
} from "lucide-react"
import type { LucideIcon } from "lucide-react"

export const REPO_URL = "https://github.com/Snehal1112/rocketvault"
const DOCS_BRANCH = "v-4.0.0"
export const DOCS_URL = `${REPO_URL}/blob/${DOCS_BRANCH}/docs/admin-manual.html`
export const API_DOCS_URL = `${REPO_URL}/blob/${DOCS_BRANCH}/docs/api-developer-guide.md`

export const SECTIONS = [
  { href: "#why", label: "Why" },
  { href: "#resources", label: "Resources" },
  { href: "#usage", label: "Usage" },
  { href: "#access", label: "Access" },
  { href: "#roles", label: "Roles" },
  { href: "#operations", label: "Operations" },
  { href: "#boundaries", label: "Limits" },
  { href: "#start", label: "Get started" },
] as const

export const REASONS = [
  {
    term: "Your infrastructure",
    body: "One Go binary on infrastructure you control. Nothing leaves your network, so it satisfies data-residency rules and runs air-gapped.",
  },
  {
    term: "No cloud account",
    body: "No subscription, no tenant, no per-operation billing. The cost of a vault is the machine you already run.",
  },
  {
    term: "Familiar model",
    body: "Vaults, versioned secrets, key operations, and the built-in role names all follow Azure Key Vault. What you know there still applies here.",
  },
  {
    term: "Source you can read",
    body: "MIT licensed. The code holding your secrets is code you can audit and change.",
  },
]

export const REQUEST_FLOW = [
  "Request",
  "Authenticate + authorize",
  "Encrypted store",
] as const

export const QUICKSTART = [
  {
    title: "Get the binary",
    body: "Run the image, or build from source with Go 1.24.",
    code: `docker compose up -d

# or, from a clone:
go build -o rocketvault .`,
  },
  {
    title: "Configure",
    body: "Copy the template and generate your own master key and bootstrap token.",
    code: `cp .rocketvault.yaml.example .rocketvault.yaml
openssl rand -base64 32`,
  },
  {
    title: "Start the server",
    body: "It reads that one config file and nothing else.",
    code: `./rocketvault serve

curl -s localhost:8774/api/v1/health/live`,
  },
  {
    title: "Create the first admin",
    body: "The bootstrap token works once, then it is consumed. There is no HTTP route for this.",
    code: `rocketvault users admin \\
  --admin-username admin \\
  --admin-password <password> \\
  --bootstrap-token <token>`,
  },
  {
    title: "Register TOTP and sign in",
    body: "The previous step returns a TOTP secret. Register it in an authenticator app; every login needs a code from it.",
    code: `rocketvault users login \\
  --username admin --password <password> --totp-code 123456

rocketvault secrets create db-password 's3cr3t'`,
  },
]

/*
 * Everything below is drawn from docs/admin-manual.html and
 * docs/api-developer-guide.html. Keep it in step with those documents.
 */

export type Resource = {
  icon: LucideIcon
  title: string
  body: string
  details: string[]
}

export const RESOURCES: Resource[] = [
  {
    icon: Lock,
    title: "Secrets",
    body: "Values encrypted at rest, retrieved over the API or the CLI so they never live in your code or config.",
    details: [
      "Every write creates a version, and old versions stay readable",
      "Tags, content types, expiry, and activation dates",
      "Rotation policies with optional auto-rotate, run by a scheduler",
      "Generate random values, and bulk export or import a whole vault",
      "Deleted secrets stay recoverable until purged",
    ],
  },
  {
    icon: KeyRound,
    title: "Keys",
    body: "Sign, verify, encrypt, decrypt, wrap, and unwrap without the private key ever leaving the vault.",
    details: [
      "RSA 2048/3072/4096 and ECDSA P-256, P-384, P-521",
      "RS, PS, and ES signatures at 256, 384, and 512",
      "RSA-OAEP and RSA-OAEP-256 for encryption",
      "Import an existing RSA or ECDSA key from a JWK",
    ],
  },
  {
    icon: FileBadge,
    title: "Certificates",
    body: "Issue X.509 certificates that are self-signed, or signed by a CA certificate you hold in the same vault. No public CA, no ACME.",
    details: [
      "Issuance and renewal policy stored with the certificate",
      "A scheduled scan renews certificates before they expire",
      "A signing CA is rejected unless it carries the CA and keyCertSign bits",
      "Soft-delete and restore, like secrets and keys",
    ],
  },
]

export type AccessItem = {
  icon: LucideIcon
  term: string
  body: string
}

export const ACCESS_ITEMS: AccessItem[] = [
  {
    icon: LogIn,
    term: "Sign in",
    body: "Username and password with TOTP two-factor. OIDC single sign-on against your own identity provider can be turned on in configuration; it issues the same session local login does, so nothing downstream behaves differently.",
  },
  {
    icon: Cpu,
    term: "Machine identities",
    body: "Service accounts get tokens through the OAuth2 client-credentials grant. A running application authenticates with a client ID and secret, never a human's credentials.",
  },
  {
    icon: Ban,
    term: "Explicit denies",
    body: "Access policies are evaluated before role grants, so a deny overrides a grant that would otherwise allow the operation.",
  },
  {
    icon: Boxes,
    term: "Isolated vaults",
    body: "One instance hosts any number of vaults, each with its own secrets, keys, certificates, and grants. Every deployment ships with a default vault.",
  },
  {
    icon: Power,
    term: "Disable a vault",
    body: "Disabling a vault rejects every request against it without deleting anything, which is what you reach for during an incident. The default vault cannot be deleted at all.",
  },
  {
    icon: EyeOff,
    term: "Absent and forbidden look alike",
    body: "A resource you hold no role over returns 404, never 403. The two are indistinguishable, so no one can map a vault by reading status codes.",
  },
]

export type Operation = {
  icon: LucideIcon
  term: string
  body: string
}

export const OPERATIONS: Operation[] = [
  {
    icon: RotateCcw,
    term: "Soft-delete and purge",
    body: "Deleted items stay recoverable for a per-vault retention window, 30 days by default. Purge protection can block permanent deletion of a vault or a single item, and purge is a separate permission.",
  },
  {
    icon: DatabaseBackup,
    term: "Backup and restore",
    body: "A whole-database backup from the CLI, or per-item backup and restore over the API. Per-item blobs are base64url-encoded, not encrypted, so treat them as sensitive.",
  },
  {
    icon: ScrollText,
    term: "Audit and compliance",
    body: "Every security-relevant action is recorded in a hash-chained log, and each query returns an integrity flag from re-verifying the chain. Export a SOC 2 or GDPR report over a date range.",
  },
  {
    icon: Activity,
    term: "Health and metrics",
    body: "Liveness, readiness, and database probes. A Prometheus endpoint can be enabled in configuration.",
  },
  {
    icon: Gauge,
    term: "Rate limiting",
    body: "Per-IP limits, tighter on the authentication endpoints, plus a per-vault budget so one busy vault cannot starve the others.",
  },
  {
    icon: Layers,
    term: "Schema migrations",
    body: "Run from the CLI, with commands to check status or step to a specific version.",
  },
  {
    icon: HardDrive,
    term: "HSM support",
    body: "Back keys with a PKCS#11 hardware module. Symmetric AES keys require one, matching Azure's own restriction.",
  },
  {
    icon: Lock,
    term: "TLS",
    body: "The server terminates TLS itself. Point server.tls at a certificate and key, or run it behind a proxy you already operate.",
  },
  {
    icon: Database,
    term: "SQLite or PostgreSQL",
    body: "SQLite for development, PostgreSQL for production, selected by configuration rather than a separate build.",
  },
]

export type Integration = {
  icon: LucideIcon
  term: string
  body: string
}

export const INTEGRATIONS: Integration[] = [
  {
    icon: Globe,
    term: "REST API",
    body: "Versioned under /api/v1, with JWT bearer authentication.",
  },
  {
    icon: Terminal,
    term: "CLI",
    body: "Vault, role, rotation, and resource management, plus a whole-database backup the API does not offer. Runs against a local instance; remote mode currently covers secrets only.",
  },
  {
    icon: Braces,
    term: "Go client",
    body: "The vaultclient package fetches and caches secrets for your service.",
  },
  {
    icon: Plug,
    term: "MCP server",
    body: "Exposes the vault to Claude Code and Claude Desktop. Read-only unless you enable the write, crypto, and secret-value tiers.",
  },
  {
    icon: Workflow,
    term: "CI/CD",
    body: "Service-account tokens let a pipeline read exactly the secrets it needs.",
  },
]

export const BOUNDARIES = [
  "One instance, with no replication and no automatic failover. Recovery means restoring from backup.",
  "Certificates are self-signed or signed by a CA you hold in the vault. There is no public-CA integration, no ACME, and no way to import an existing certificate.",
  "Audit logs stay on the instance. There is no cloud log sink and nothing is pushed anywhere.",
  "The software crypto is not FIPS-validated, and a PKCS#11 HSM behind it is not FIPS 140-3 Level 3 certified.",
  "Confidential-computing key release does not exist, which is why one of Azure's twelve built-in roles is absent.",
] as const

export type TerminalLine = {
  prompt?: boolean
  text: string
  muted?: boolean
}

export const HERO_SESSION: TerminalLine[] = [
  { prompt: true, text: "rocketvault vaults create payments" },
  { prompt: true, text: "rocketvault vault-access grant alice \\" },
  { text: '  --vault payments --role "Key Vault Secrets Officer"' },
  { prompt: true, text: "rocketvault secrets create db-password 's3cr3t' \\" },
  { text: "  --vault payments --tags env:prod" },
  { prompt: true, text: "rocketvault secrets list --vault payments" },
]

export const CLI_SAMPLE = `# Sign in once. The session is cached, and every later
# command refreshes it for you.
rocketvault users login \\
  --username alice --password <password> --totp-code 123456

# Grant Alice one role, in one vault, not across the instance.
rocketvault vault-access grant alice \\
  --vault payments \\
  --role "Key Vault Secrets Officer" \\
  --principal-type user

# Write a secret, then read it back.
rocketvault secrets create db-password 's3cr3t' \\
  --vault payments \\
  --tags env:prod

rocketvault secrets list --vault payments`

export const REST_SAMPLE = `curl -X POST \\
  https://vault.internal/api/v1/vaults/payments/secrets \\
  -H "Authorization: Bearer $ROCKETVAULT_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "db-password",
    "value": "s3cr3t",
    "tags": ["env:prod"]
  }'`

export const GO_SAMPLE = `client, _ := vaultclient.New(vaultclient.Config{
    URL:          "https://vault.internal",
    ClientID:     "my-app",
    ClientSecret: os.Getenv("VAULT_CLIENT_SECRET"),
    Secrets: []vaultclient.SecretMapping{
        {Name: "DB_PASSWORD", UUID: "<uuid>"},
    },
})

secrets, _ := client.GetMany(ctx, []string{"DB_PASSWORD"})`

/* The eleven built-in vault roles, from the manual's RBAC section. */
export const VAULT_ROLES = [
  "Key Vault Administrator",
  "Key Vault Reader",
  "Key Vault Secrets Officer",
  "Key Vault Secrets User",
  "Key Vault Crypto Officer",
  "Key Vault Crypto User",
  "Key Vault Crypto Service Encryption User",
  "Key Vault Certificates Officer",
  "Key Vault Certificate User",
  "Key Vault Purge Operator",
  "Key Vault Data Access Administrator",
] as const

export const ACCOUNT_ROLE_COLUMNS = [
  "Secrets",
  "Keys",
  "Certificates",
  "Users",
] as const

/* "full" is create, read, update, delete and list. "—" is no access. */
export const ACCOUNT_ROLES = [
  { role: "admin", cells: ["full", "full", "full", "full"] },
  { role: "user", cells: ["read", "read", "read", "—"] },
  { role: "service_account", cells: ["read", "read", "read", "—"] },
  { role: "secrets_manager", cells: ["full", "—", "—", "—"] },
  { role: "crypto_manager", cells: ["—", "full", "—", "—"] },
  { role: "certificate_manager", cells: ["—", "—", "full", "—"] },
] as const
