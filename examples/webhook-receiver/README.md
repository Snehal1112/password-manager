# webhook-receiver

An example receiver for RocketVault's per-vault webhook, showing how to
verify a signed delivery. Source of the wire contract:
`docs/superpowers/specs/2026-08-20-webhook-delivery-primitive-design.md`.

## Status: the contract is fixed, delivery is not built yet

`rocketvault vault-webhook set` today only *stores* a URL and mints a signing
secret — there is no outbound HTTP call anywhere in the codebase yet. No
matter what URL you configure, RocketVault will not call it. The design spec
above is `Status: Proposed`.

This example is still useful now: it implements the signature scheme exactly
as specified, so it's ready to receive a real delivery once it ships, and it
includes a `-simulate` mode that sends itself (or any target) a correctly
signed test event today, so you can exercise the verification logic
end-to-end without waiting for that feature.

## Files

- `main.go` — the receiver (`-listen`) and a delivery simulator (`-simulate`)
- `signature.go` — `Sign`/`Verify`, implementing the spec's HMAC scheme
- `signature_test.go` — a golden signature vector plus rejection cases

## Try it

**1. Get a real signing secret from a running RocketVault instance** (or use
any string for a pure local test — see step 2's alternative):

```bash
rocketvault vault-webhook set --vault demo --url https://numericlabs.lxd/hooks/rocketvault
#   Signing Secret: <43-char string — this is SECRET, save it exactly>
export ROCKETVAULT_WEBHOOK_SECRET='<the secret above>'
```

**2. Start the receiver:**

```bash
go run . -listen :8090
# or, without a real vault: go run . -listen :8090 -secret test-secret-for-local-use
```

**3. In a second terminal, simulate a delivery** — this builds and sends a
`webhook.test` event exactly as the real sender is specified to, so it's a
genuine test of the verification path, not a stub:

```bash
go run . -simulate http://localhost:8090/hooks/rocketvault -vault demo
```

The receiver logs `verified event: type=webhook.test id=... vault=demo ...`.
Change `-secret` on the simulate call to something wrong and it logs
`rejected delivery: signature does not match` with a `401` instead — try
both to see the negative case.

**4. Point it at `https://numericlabs.lxd`** once you have a real receiver
deployed there:

```bash
go run . -simulate https://numericlabs.lxd/hooks/rocketvault -vault demo
```

This only proves your *receiver's* verification logic is correct — it still
does not mean RocketVault will ever call that URL on its own, until the
delivery sub-project above ships.

## The wire contract this implements

```
X-RocketVault-Signature: t=<unix-seconds>,v1=<hex hmac-sha256>
```

```
signed_string = "<unix-seconds>" + "." + <raw request body bytes>
v1 = hex(HMAC_SHA256(key = signing_secret, message = signed_string))
```

Two easy-to-miss details, both load-bearing:

- The HMAC key is the **43-character base64url secret string exactly as
  printed** by `vault-webhook set` — not the bytes it decodes to.
- The signed message is built from the **exact raw body bytes** as received.
  Parsing the JSON and re-marshaling it before verifying will usually change
  byte-for-byte formatting (key order, spacing) and break the signature.

See the design spec for the full envelope shape, replay-tolerance guidance,
and why response bodies should never be inspected or logged by a receiver.
