# RocketVault MCP Server

`rocketvault mcp` serves your vault to an MCP client such as Claude Code or
Claude Desktop, so an assistant can answer questions like *"which secrets in
prod expire this month?"* or *"who was granted Crypto Officer last week?"*
without you pasting output into a chat window.

It talks to a RocketVault API server over HTTP, so every call is authorized by
the same middleware any other API client goes through, and every call lands in
the audit log.

## Quick start

The server needs a running RocketVault instance and an identity.

```bash
# 1. Start the API server, if it is not already running.
rocketvault serve &

# 2. Log in. The session is cached under ~/.rocketvault/sessions/.
rocketvault users login --username admin

# 3. Confirm the MCP server can start and see the vault.
rocketvault mcp --check
```

`--check` prints the server it will talk to, the identity it will act as,
whether that identity works, and the exact list of tools it would expose. If
something is wrong, this is where you find out — a misconfiguration otherwise
surfaces inside the host as an unexplained startup failure.

Then register it with Claude Code, in `~/.claude.json` or your project's
`.mcp.json`:

```json
{
  "mcpServers": {
    "rocketvault": {
      "command": "/absolute/path/to/rocketvault",
      "args": ["mcp"]
    }
  }
}
```

The path must be absolute — the host does not resolve it against your shell's
`PATH`.

## What it exposes by default

Ten read-only tools, and no secret values:

| Tool | What it does |
|---|---|
| `list_secrets` | Names, versions and tags. Never values. |
| `get_secret` | Metadata, expiry, tags and version history. |
| `list_keys` | Key names, types and status. |
| `get_key` | Metadata, public JWK components, versions, rotation policy. |
| `list_certificates` | Certificates with expiry and renewal settings. |
| `get_certificate` | Metadata and issuance policy. |
| `list_deleted` | Soft-deleted secrets, keys or certificates. |
| `list_vaults` | Vaults with retention and purge-protection settings. |
| `list_role_assignments` | Who holds which role in a vault. |
| `query_audit_log` | Audit entries, filterable by time, action or outcome. |

Nothing here can change your vault. Every mutating capability is off until you
turn it on.

## Enabling more

Capability tiers live in the `mcp` section of `.rocketvault.yaml`. Each is
independent, and all default to `false`:

| Flag | Adds | Tools |
|---|---|---|
| `allow_write` | Create and update | 9 |
| `allow_destructive` | Delete, purge, revoke | 4 |
| `allow_crypto` | Sign, verify, encrypt, decrypt | 4 |
| `allow_secret_values` | `get_secret` can return plaintext | 0 (changes an existing tool) |

```yaml
mcp:
  vault: default
  allow_write: true
  allow_destructive: false
  allow_crypto: false
  allow_secret_values: false
```

Run `rocketvault mcp --check` after any change to confirm the tool count moved
the way you expected.

These flags only ever **narrow** what the authenticated principal could already
do. They cannot grant access the vault's role assignments do not — a tool that
passes the local gate can still get a 403.

### Pinning the blast radius

`allowed_vaults` restricts the server to a set of vaults, regardless of what
the principal could otherwise reach:

```yaml
mcp:
  vault: prod
  allowed_vaults: ["prod"]
```

Vaults outside the list are hidden from `list_vaults` and refused before any
request is made.

### Destructive confirmation

With `confirm_destructive: true` (the default), `delete_item`, `purge_item`,
`purge_vault` and `revoke_vault_role` require the caller to echo the exact
resource name. Leave it on. It costs one argument and it stops a destructive
call triggered by text the model read out of your vault.

## Identity

The server holds one identity for its whole lifetime. There is no per-user
authentication — the server is a child process of your MCP client, running as
you.

**Cached session** (the default, and fine for local use): whatever
`rocketvault users login` cached. The agent then acts as *you*, which means its
actions are indistinguishable from yours in the audit log.

**Service account** (use this for anything else): a dedicated principal with
its own role grants, so agent activity is attributable and its permissions are
exactly what you chose.

There is **no CLI command to create a service account** — the only way is the
REST API. Create one against a running server, authenticated as an admin:

```bash
# Log in, then read the cached session token. The `current` pointer holds
# "<serverKey>|<username>"; the session file is named "<serverKey>__<username>.json".
rocketvault users login --username admin

SESSIONS="$HOME/.rocketvault/sessions"
TOKEN=$(jq -r .token "$SESSIONS/$(sed 's/|/__/' "$SESSIONS/current").json")

curl -sS -X POST http://127.0.0.1:8774/api/v1/service-accounts \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"mcp-agent"}'
```

The response contains `client_id` and `client_secret`. **The secret is shown
once and never again** — copy it now.

Then grant the account only what it needs. Note that the principal is a
positional argument, and a service account needs `--principal-type`:

```bash
rocketvault vault-access grant mcp-agent \
  --role "Key Vault Reader" \
  --principal-type service_account \
  --vault prod
```

Run `rocketvault vault-access roles` to see the available role names.

Then configure it, keeping the secret out of the config file:

```yaml
mcp:
  client_id: "<the client_id printed above>"
  require_service_account: true
```

```bash
export ROCKETVAULT_MCP_CLIENT_SECRET='<the client_secret printed above>'
```

The environment variable takes precedence over `mcp.client_secret` in the YAML.
`require_service_account: true` makes the server refuse to fall back to your
session, so it cannot quietly start as you.

## Remote servers

```bash
rocketvault mcp --server https://vault.example.com
```

`ROCKETVAULT_ADDR` and named contexts (`rocketvault context use prod`) work
too. With none of them set, the server talks to `http://127.0.0.1` on the port
from `server.listen_addr`, and says so on stderr at startup.

## Known limitation: audit logs need admin

`query_audit_log` calls a route that requires the **global admin role**. No
per-vault role grants it — not `Key Vault Reader`, not even
`Key Vault Data Access Administrator`.

So a least-privilege service account, which is otherwise the right setup, will
get a permission error from that one tool every time. That is the API's design,
not a bug in the MCP server.

You have two honest options, and the second is often the better one:

1. Run the server as an admin principal, accepting a much broader grant than
   the other nine tools need.
2. Leave `query_audit_log` unusable and read audit logs with the CLI when you
   need them.

## Troubleshooting

**The client says the server failed to start.** Run `rocketvault mcp --check`.
It reports the actual cause; the host cannot, because the failure happens
before any protocol exchange.

**"no identity is configured".** Either run `rocketvault users login`, or set
`mcp.client_id` and `ROCKETVAULT_MCP_CLIENT_SECRET`.

**A tool returns a permission error.** The message names the missing data
action and a role that would grant it. Grant that role in that vault:

```bash
rocketvault vault-access grant mcp-agent \
  --role "Key Vault Secrets User" \
  --principal-type service_account \
  --vault prod
```

**A tool you expected is missing.** Its tier is off. `--check` lists the
enabled tiers and every exposed tool.

**Everything is being rate limited.** `mcp.rate_limit` bounds calls per minute
— 120 reads and 20 writes by default. A loop trips it. The limits are there so
a runaway agent degrades its own calls rather than your vault.

## Diagnostics

The server writes structured logs to stderr, one line per tool call, with the
tool name, outcome, duration and a correlation ID. That ID travels to the API
as a request header, so a tool call can be traced through to the audit entry it
produced.

Tool arguments are never logged: they can carry secret values.
