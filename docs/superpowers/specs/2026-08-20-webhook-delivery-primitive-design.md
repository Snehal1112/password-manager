# Webhook Delivery Primitive — Design

**Date:** 2026-08-20
**Status:** Proposed
**Branch target:** `v-4.0.0`
**Predecessor:** `docs/superpowers/specs/2026-08-19-vault-webhook-config-design.md`
(sub-project 1, merged as `d9589dc`, `f034a6a`, `6b3a910`)

Sub-project 2 of the 6-part decomposition closing `.claude/known-bugs.md` § B27
(`notify_before_expiry_days` is persisted and echoed back, but nothing ever
sends a notification).

Sub-project 1 built per-vault webhook *configuration* — an https URL, an
enabled flag, and a server-minted signing secret stored encrypted and shown
once — and nothing reads it. That feature is currently inert. This sub-project
builds the thing that sends.

## Goal

Deliver a signed JSON event over HTTPS to a vault's configured webhook, safely
enough to run inside a secrets manager, and make a failing webhook visible to
the operator who configured it.

## Non-goals

- **No publishers.** The near-expiry sweep is sub-project 3; secrets'
  `sendReminder` wiring is 4; certificate expiry warnings are 5. After this
  lands the only caller is `TestSend`, which is precisely what sub-project 1
  deferred to here rather than ship a route that was authorized and reachable
  but inert.
- **No durability.** No outbox table, no delivery worker, no at-least-once
  guarantee across restarts. See "Why best-effort is sufficient" below.
- **No delivery history table.** Per-send forensics would grow unboundedly and
  needs its own retention policy.
- **No provider-specific formatting.** A generic signed webhook only; Slack and
  PagerDuty shapes are a later concern.
- **`ExpirationService` stays as it is.** `internal/services/secrets/expiration_service.go`
  is unwired dead code (`NewExpirationService` is never called from the
  container or any `cmd/` bootstrap). Reviving or deleting it is not this
  sub-project's call.

## Design decisions

| Decision | Choice | Rationale |
|---|---|---|
| Event scope | Ship only the expiry-warning use case, but define the wire format as a **versioned event envelope** with a `type` field | Decided during brainstorming. YAGNI applies to machinery, not to a public contract: the envelope is the one thing that cannot change once customers implement receivers against it. Sub-projects 3–5 add new `type` values without touching it. |
| Delivery durability | **Best-effort.** Send inline, retry a few times in-process, record the outcome, do not persist undelivered events | Expiry warnings replay naturally: the sweep runs on a cadence against current state, so a failed send today is re-attempted tomorrow with no machinery. Point-in-time events (rotation failures, audit streaming) have no such replay and *would* need an outbox — that is a cost to pay when the first such publisher arrives, not now. |
| Network policy | Refuse loopback, link-local and unspecified addresses; **allow RFC1918 private ranges** | RocketVault is self-hosted, so an internal receiver on `10.x.x.x` is the ordinary case and blocking it by default would break a fresh install. `169.254.169.254` (cloud metadata) is never a legitimate webhook target. |
| Where the policy is enforced | On the **resolved IP at dial time**, via `net.Dialer.Control` | Validating the hostname at configuration time does not prevent this: DNS can resolve benign at config time and hostile at send time. The `Control` hook runs after resolution and before connect, on every attempt, so rebinding is covered. |
| Redirects | **Disabled** (`CheckRedirect` returns `http.ErrUseLastResponse`) | A webhook endpoint that redirects is misconfigured. Refusing removes a bypass class outright; the `Control` hook would catch a redirect to a blocked IP regardless, so this is defence in depth over a working guard, not the guard itself. |
| Response body | **Never surfaced** to the operator, in `TestSend` or anywhere else | This is the single thing that would turn a blind SSRF into an exfiltration primitive. Deliberately trades debuggability: the operator reads their own receiver's logs instead. |
| Failure visibility | Four status columns on `vault_webhook_configs`, returned by `GET` and the CLI | Best-effort delivery has one bad failure mode — a silently broken webhook is indistinguishable from "nothing is expiring", so an operator can be uncovered for months while believing they are covered. Columns on an existing table avoid a new table and its retention question. |
| Package placement | New `internal/services/webhook/` | Vaults owns configuration; this owns delivery. The dependency runs one way — the sender reads vault config, never the reverse — so sub-project 3's sweep can depend on the sender without pulling in vault lifecycle. |
| Signature scheme | Stripe-style `t=<unix>,v1=<hex>` over `<timestamp>.<body>` | Well-understood and widely implemented; receivers can often reuse existing verification code. The timestamp in the signed string is what lets a receiver reject replays. |
| Envelope format | A small explicit RocketVault envelope, **not CloudEvents 1.0** | CloudEvents would buy interop with existing tooling, but obliges us to track a spec, and a half-implementation is worse than either. Revisit if users turn out to run CloudEvents infrastructure. |

## The wire contract

This section is the public contract. Everything else in this document can be
refactored freely; this cannot change without breaking deployed receivers.

### Envelope

```json
{
  "version": "1",
  "id": "8f14e45f-ea3f-4b21-9c1d-0a1b2c3d4e5f",
  "type": "key.near_expiry",
  "time": "2026-08-20T14:32:56Z",
  "vault": "prod",
  "data": {}
}
```

- `version` — envelope version, currently `"1"`. Bumped only for a breaking
  change to the envelope itself, never for a new `type`.
- `id` — UUIDv4, unique per event. Receivers use it to deduplicate, which
  matters because retries can deliver the same event more than once.
- `type` — dotted event type. This sub-project defines exactly one:
  `webhook.test`. Sub-projects 3–5 add `key.near_expiry`,
  `secret.near_expiry`, and `certificate.near_expiry`.
- `time` — RFC3339 UTC, when the event was generated (not when it was sent; a
  retried event keeps its original `time`).
- `vault` — the vault's name, for receivers routing by vault.
- `data` — type-specific object. Empty for `webhook.test`.

`Content-Type` is `application/json`.

### Signature

```
X-RocketVault-Signature: t=1755689576,v1=3f8a...
X-RocketVault-Event-Id: 8f14e45f-ea3f-4b21-9c1d-0a1b2c3d4e5f
X-RocketVault-Event-Type: webhook.test
```

The signed string is the Unix timestamp, a literal `.`, then the **exact raw
request body**:

```
signed_string = "1755689576" + "." + <raw body bytes>
v1 = hex(HMAC_SHA256(key = signing_secret, message = signed_string))
```

**The HMAC key is the 43-character base64url secret string exactly as returned
to the operator — not the 32 bytes it decodes to.** This is pinned by a comment
on `mintSecret` in sub-project 1 and restated here because every receiver
implementation must agree. The string is what the operator copies, and
therefore what they will paste into their receiver's configuration.

`t` is the send attempt's timestamp, so it differs between retries of the same
event while `id` stays constant. Receivers should reject a signature whose `t`
is outside their tolerance (5 minutes is a reasonable default) to limit replay,
and should compare `v1` with a constant-time comparison.

The two convenience headers duplicate envelope fields so a receiver can route
or deduplicate before parsing the body. They are **not** covered by the
signature beyond being duplicated inside the signed body — a receiver that
trusts them without verifying the body is trusting unsigned input.

## Components

### 1. Sender (`internal/services/webhook/sender.go`, new)

```go
// Event is one deliverable occurrence. Publishers construct it; the sender
// owns the envelope's transport-level fields.
type Event struct {
    Type string          // e.g. "webhook.test"
    Data any             // marshaled into the envelope's "data"
}

// Result describes what happened, for callers that need to distinguish
// "delivered" from "there was nothing to deliver to". Publishers ignore it;
// TestSend reports it to the operator.
type Result struct {
    Delivered  bool   // true only on a 2xx response
    Skipped    bool   // true when the vault has no config, or it is disabled
    SkipReason string // "no webhook configured" / "webhook is disabled"
    StatusCode int    // receiver's status code; 0 if no response was obtained
    Attempts   int    // how many delivery attempts were made
}

type Sender interface {
    // Send delivers event to vaultID's configured webhook.
    //
    // A vault with no config, or a disabled config, returns
    // (Result{Skipped: true, ...}, nil) rather than an error: a vault without
    // a webhook is the normal case and publishers must not have to
    // special-case it. Callers that need to tell the difference -- TestSend
    // does, publishers do not -- read Result.
    Send(ctx context.Context, vaultID uuid.UUID, event Event) (Result, error)
}

func NewSender(cfg VaultWebhookConfigReader, status StatusRecorder, log *logging.Logger) Sender
```

The sender depends on two narrow interfaces rather than the concrete vault
service, so it can be tested without one and so the dependency direction stays
one-way:

```go
// VaultWebhookConfigReader is the subset of the vault webhook service the
// sender needs. Satisfied by vaults.VaultWebhookService.
type VaultWebhookConfigReader interface {
    Get(ctx context.Context, vaultID uuid.UUID) (*model.VaultWebhookConfig, error)
}

// StatusRecorder persists a delivery outcome. Satisfied by the vault webhook
// repository.
type StatusRecorder interface {
    RecordDeliverySuccess(ctx context.Context, vaultID uuid.UUID, at time.Time) error
    RecordDeliveryFailure(ctx context.Context, vaultID uuid.UUID, at time.Time, reason string) error
}
```

`Send`'s sequence:

1. Read the vault's config. Absent (`ErrWebhookNotFound`) or `Enabled == false`
   → return `Result{Skipped: true, SkipReason: ...}, nil` without sending, and
   without touching the status columns (nothing was attempted, so recording a
   failure would be false).
2. Decrypt the signing secret with `common.DecryptSecret`. **This is the only
   place in the codebase that ever holds that plaintext.**
3. Build the envelope, marshal it once, and keep the exact bytes — the
   signature covers the bytes that are sent, so it must not be re-marshaled.
4. Sign, set headers, POST with retry (below).
5. Record the outcome via `StatusRecorder`, then return.

The plaintext secret must never be logged, and must not appear in any error
returned from `Send`.

### 2. HTTP client (`internal/services/webhook/client.go`, new)

Constructed once and reused, with every timeout set explicitly:

```go
dialer := &net.Dialer{
    Timeout:   5 * time.Second,
    KeepAlive: 30 * time.Second,
    Control:   ipPolicy.Control,   // see below
}
transport := &http.Transport{
    DialContext:           dialer.DialContext,
    TLSHandshakeTimeout:   5 * time.Second,
    ResponseHeaderTimeout: 10 * time.Second,
}
client := &http.Client{
    Transport:     transport,
    Timeout:       10 * time.Second,
    CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}
```

`TLSHandshakeTimeout` is set deliberately: a hand-rolled `http.Transport`
literal leaves it at `0`, meaning unbounded, and this repository already
carries a comment about that trap at `internal/services/auth/oidc_service.go:210`.

The response body is read with an `io.LimitReader` cap (4 KiB) and discarded.
It is read at all only so the connection can be reused; its contents are never
inspected, stored, logged, or returned.

### 3. IP policy (`internal/services/webhook/ippolicy.go`, new)

```go
// IPPolicy decides whether a resolved destination address may be dialed.
type IPPolicy interface {
    Control(network, address string, c syscall.RawConn) error
}

// DefaultIPPolicy refuses loopback, link-local and unspecified addresses and
// permits everything else, including RFC1918 private ranges.
type DefaultIPPolicy struct{}
```

`Control` parses the host portion of `address` — which at this point is a
resolved IP literal, not a hostname — and rejects when any of
`ip.IsLoopback()`, `ip.IsLinkLocalUnicast()`, `ip.IsLinkLocalMulticast()`, or
`ip.IsUnspecified()` holds. `169.254.169.254` is covered by
`IsLinkLocalUnicast`. A rejection returns a static error naming the class
(`"destination address is not permitted"`), never the address itself, since
that error can reach the operator via `last_error`.

**The policy is an injectable field on the sender, defaulting to
`DefaultIPPolicy`.** This is a testability requirement, not a convenience:
`httptest.Server` listens on loopback, so a hard-wired production policy would
block every happy-path test in this package. Tests substitute a permissive
policy; a separate table test asserts the production policy rejects loopback,
link-local, metadata and unspecified addresses. Without the injection point,
the tempting fix when the happy-path tests fail is to weaken the guard.

### 4. Retry policy (`internal/services/webhook/sender.go`)

`internal/retry` already provides the machinery; this defines the tier:

```go
// webhookPolicy is ExternalServicePolicy with a shorter attempt budget and
// explicit retryable statuses.
func webhookPolicy() retry.Policy {
    p := retry.ExternalServicePolicy()
    p.MaxAttempts = 3
    p.RetryableStatuses = []int{429, 500, 502, 503, 504}
    return p
}
```

Two corrections to naive reuse, both verified against the source:

- `retry.ExternalServicePolicy()` (`internal/retry/retry.go:62`) sets
  `MaxAttempts: 5` with a 1s initial delay and a 2.0 multiplier. Combined with
  a 10s per-attempt timeout that is roughly 65 seconds of worst-case blocking
  per vault — too slow for a sweep iterating many vaults. Three attempts caps
  it near 25 seconds.
- `ExternalServicePolicy()` leaves `RetryableStatuses` **nil**. Only
  `DefaultPolicy()` (`:36`) populates it. `retry.IsRetryableStatus` iterates
  that slice, so with the external-service policy as-is it returns false for
  every status code and status-driven retry would silently never happen. The
  set `{429, 500, 502, 503, 504}` matches the existing convention at
  `retry/retry.go:36` and `retry/middleware.go:323`.

A 4xx other than 429 is never retried: a 401 or 404 is a misconfiguration that
retrying cannot fix and that would only hammer the receiver. Delivery is
wrapped with `retry.WithExponentialBackoff(ctx, webhookPolicy(), fn)`.

### 5. Status columns (`internal/db/db.go`, `model`, repository)

Four columns on `vault_webhook_configs`:

| Column | Type | Meaning |
|---|---|---|
| `last_success_at` | `TIMESTAMP NULL` | Last 2xx delivery |
| `last_failure_at` | `TIMESTAMP NULL` | Last failed delivery |
| `last_error` | `TEXT NOT NULL DEFAULT ''` | Sanitized reason for the last failure; cleared to `''` on success |
| `consecutive_failures` | `INTEGER NOT NULL DEFAULT 0` | Reset to 0 on success |

A success clears `last_error` as well as zeroing the counter. Leaving a stale
error string beside a fresh `last_success_at` would read as though the webhook
were still broken.

Registered in **both** schema paths, matching the convention sub-project 1
followed: added to the `CREATE TABLE` in `createOptimizedSchema`, and as
`ALTER TABLE vault_webhook_configs ADD COLUMN ...` statements in
`migrateSchema`'s statement slice. Repeated `ALTER`s are already tolerated —
`migrateSchema` swallows `isDuplicateColumnError` (`internal/db/db.go:921-927`).

Both recorders write a single `UPDATE` with SQL-side arithmetic rather than
read-modify-write, so concurrent sends cannot lose a count:

```sql
UPDATE vault_webhook_configs
SET last_failure_at = ?, last_error = ?, consecutive_failures = consecutive_failures + 1
WHERE vault_id = ?
```

`last_error` is a **sanitized class**, never raw output: `HTTP 502`,
`connection refused`, `timeout`, `destination address is not permitted`. It is
stored in the database and returned by `GET`, so anything landing there is
effectively readable by every config reader. It must never contain the response
body, the URL, or the signing secret.

A failure to record status never fails an otherwise-successful delivery — it is
logged and swallowed. The delivery already happened; reporting it as failed
would be worse than losing the bookkeeping.

`model.VaultWebhookConfigResponse` gains the four fields (as RFC3339 strings
and an int), so `GET` and the CLI surface them.

### 6. TestSend

- **HTTP:** `POST /vaults/{name}/webhook/test`, registered on
  `api.BaseRoutes.Vaults` beside the existing three, using the same
  resolve-then-authorize prologue via `resolveAndAuthorizeVault`.
- **CLI:** `rocketvault vault-webhook test --vault <name>`, authorized by the
  package-local `requireCanManageVault`.

Both send a `webhook.test` event with empty `data` through the identical path,
so a passing test genuinely exercises signing, the IP policy, timeouts and
retry.

The response reports `Result` — delivered or skipped, the HTTP status code, the
attempt count, and the sanitized error class — **never the receiver's response
body**. A test send updates the status columns like any other delivery: it is a
real delivery to the same endpoint, and an operator who has just fixed their
receiver expects the failure state to clear.

A skipped result must **not** be reported as success, or `vault-webhook test`
on a vault with no webhook would tell the operator everything is fine. Mapping:

| `Result` | HTTP | CLI |
|---|---|---|
| `Delivered` | `200` with the result body | prints the status code and "delivered" |
| `Skipped`, no config | `404` (`webhook config`) | "no webhook configured for vault %q" |
| `Skipped`, disabled | `409` | "webhook for vault %q is disabled" |
| delivery failed | `502` with status code and error class | non-zero exit, prints both |

`502` rather than `500` for a failed delivery: the fault is the upstream
receiver's, not RocketVault's, and the distinction matters to whoever is
reading the response.

An audit record is written for a test send, attributed to the acting principal,
matching how sub-project 1 audits configuration changes.

## Testing

- **Golden signature vector.** Fixed secret, fixed timestamp, fixed body,
  asserted against an exact hex digest. This is the only thing standing between
  a future refactor and silently breaking every deployed receiver.
- **Independent verification.** A test receiver that verifies the HMAC the way
  a customer's would — reconstructing `t.body` from what arrived — proving the
  scheme is implementable from this document rather than merely self-consistent.
- **IP policy table test** against the *production* policy: loopback (v4 and
  v6), `169.254.169.254`, link-local, and unspecified are rejected; a public
  address and an RFC1918 address are permitted.
- **Retry behaviour**, counting requests on an `httptest.Server`: 500 is
  retried up to the attempt cap, 404 is attempted exactly once, 429 is retried.
- **Timeout**, via a handler that sleeps past the client bound.
- **No config and disabled config** make no HTTP request at all, return
  `Result{Skipped: true}` with no error, and leave the status columns
  untouched.
- **Skip is not success at the edges**: `TestSend` on a vault with no webhook
  returns 404 (not 200), and on a disabled webhook returns 409 — the
  regression test for the trap where a skipped delivery reads to the operator
  as a working one.
- **Status recording**: success sets `last_success_at` and zeroes
  `consecutive_failures`; failure increments it and stores a sanitized reason.
- **Leak tests**: neither the plaintext signing secret nor the response body
  appears in `last_error`, in any log entry, or in the `TestSend` response.
- **API and CLI**: `POST .../webhook/test` returns 403 without
  `CanManageVault` and 404 for an unknown vault, and the service is not reached
  in either case.

## Verification gate

```
go build ./...
go vet ./...
go test ./...
```

## Documentation

- **`docs/webhook-receivers.md` (new)** — the envelope, the signature scheme,
  the base64url-string-is-the-key rule, replay guidance, and worked verification
  code. A public wire contract nobody can implement against is useless, so this
  ships with the feature rather than after it.
- **`docs/api-specification.yaml`** — the `POST /vaults/{name}/webhook/test`
  endpoint and the four new `GET` response fields. An OpenAPI drift test
  (`api/openapi_drift_test.go`) fails when a registered route has no spec entry,
  so this must land in the same change as the route.
- **`.claude/known-bugs.md` § B27** — record that delivery now exists while B27
  stays **open**: `notify_before_expiry_days` still has no effect, because no
  publisher calls the sender until sub-project 3.
- **`.claude/roadmap-azure-parity-and-beyond.md`** — Phase 3's "native
  webhook/notification system" entry is now partially delivered; note what
  exists and what remains.
- **`docs/usage-guide.md`** — still deferred to whichever sub-project makes a
  notification actually reach an operator end-to-end. A pre-commit hook already
  reports this guide as stale for unrelated sections; that warning is
  informational and predates this work.
