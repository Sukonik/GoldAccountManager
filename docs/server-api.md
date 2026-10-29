# Confirmation server API

The reference for package [`server`](../server) and `goldd serve`. It turns a confirmed email address into a signed
attestation that the user keeps in their packet. See [verification](verification.md) for why.

> **Status: Phase 1, first slice.** Email magic link only. State is in memory, so run **one instance**, and know that a restart
> forgets unfinished confirmations **and app quotas** (see [Known limits](#known-limits)).

## The flow

1. The app calls `start` with the address and the packet id. The server emails a link and returns a **challenge id** and a
   secret **pickup** value. Only the caller that started the flow has the pickup value.
2. The user opens the link. It shows a page with a **Confirm** button. Opening the link changes nothing, because email
   scanners and link previews open every link in a message.
3. Pressing **Confirm** checks the token, applies the app's quota, and signs an attestation for that packet.
4. The caller polls `pickup` and receives the attestation **once**. The app puts it in the packet.

## Endpoints

All responses carry `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (the link
holds a secret) and `X-Frame-Options: DENY`, plus a restrictive `Content-Security-Policy`. Error bodies are
`{"error": "<code>", "message": "<fixed text>"}` and never echo request input.

### `POST /v1/apps/{app}/confirm/start`

`Content-Type: application/json`, at most 4 KiB, unknown fields rejected.

| Field | |
|---|---|
| `kind` | `"email"` |
| `target` | the address. Normalized (lowercase, ASCII only, strict form) before use |
| `packetId` | the packet the attestation will be bound to (`pk_…`) |
| `method` | optional, `"email-link"` |

`202` → `{"challengeId": "ch_…", "pickup": "<secret>", "expiresIn": 1800}`. The reply has the same shape whether or not the
address was seen before.

| Status | `error` | When |
|---|---|---|
| 400 | `bad_request`, `unsupported` | bad JSON, address or packet id; a kind or method the app does not offer |
| 404 | `unknown_app` | no such app |
| 413 / 415 | `too_large`, `unsupported_media_type` | body over 4 KiB; wrong content type |
| 429 | `rate_limited` | see [Limits](#limits). `Retry-After` is set |
| 502 | `mail_failed` | the email could not be sent. Nothing is left behind |
| 503 | `busy` | too many unfinished confirmations. `Retry-After` is set |

### `GET /v1/confirm/link?c=…&t=…`

The page the email links to. HTML. `200` shows a **Confirm** button. `404` means the link is invalid, used or expired. It
**never** confirms anything.

### `POST /v1/confirm/link`

Form fields `c` and `t` (at most 2 KiB). HTML. `200` for confirmed, "app is full" or "on the waitlist"; `400` when the link is
invalid or expired. Links work once, and five wrong tokens burn the challenge.

### `POST /v1/apps/{app}/confirm/pickup`

JSON `{"challengeId": "ch_…", "pickup": "<secret>"}`.

| Status | Body |
|---|---|
| 202 | `{"status": "pending"}`. The user has not pressed Confirm yet |
| 200 | `{"status": "confirmed", "attestation": {…}}`, handed over **once** |
| 200 | `{"status": "full"}` or `{"status": "waitlisted"}`, once |
| 404 | `{"error": "not_found"}`. **Identical** for a wrong id, a wrong secret, another app and an expired challenge |
| 429 | polling is limited to 120 per 10 minutes per challenge |

### `GET /v1/keys`

`{"keys": [{"keyId": "k1", "algorithm": "ed25519", "publicKey": "<base64url>"}]}`. Apps use it to check attestations with
`verify.Checker`.

### `GET /healthz` · `GET /dev/inbox`

`/healthz` returns `ok`. `/dev/inbox` exists only with `-dev` and lists recent emails, which contain live links. Never enable it
in production.

## Apps, quotas and the free tier

Each app is its own isolated space with its own secret. The same address in two apps gives two unrelated **subjects**
(`verify.Subject`, an HMAC under the app's secret), so apps cannot be linked.

| Setting | Meaning |
|---|---|
| `maxSubjects` | cap on different confirmed addresses. `0` means no cap. This is the free-tier limit |
| `onLimit` | `block` (default) or `waitlist` for a new address once the app is full |
| `attestationDays` | how long an attestation is valid. Default 365 |
| `origins` | web origins allowed to call the API from a browser (CORS). None by default |

The quota is applied when the user **presses Confirm**, not at `start`, so `start` cannot be used to ask "is this address
already a member". People already in a full app are always admitted again, so a full app never locks out its own users.

## Limits

| What | Limit |
|---|---|
| `start` per client address, per app | 20 per hour |
| `start` per email address, per app | 5 per hour (so nobody can mail-bomb a victim) |
| `pickup` per challenge | 120 per 10 minutes |
| Link and challenge lifetime | 30 minutes |
| Unfinished confirmations | 20 000, then `503 busy` |
| Wrong tokens per link | 5 |

The client address is the connection's address. `X-Forwarded-For` is ignored unless you turn on `TrustForwardedFor`, and then
**only its last entry** is used, which is the one your own proxy appended.

## Running it

```bash
goldd serve -dev                    # demo: throwaway keys, two demo apps, links printed instead of emailed
goldd keygen -app notes-demo        # real deployment: makes the secrets below
goldd serve -config goldd.json      # real deployment
```

**Build it with the newest Go patch release.** The server runs `net/http`, `crypto/tls` and `crypto/x509`, and `govulncheck`
finds dozens of standard-library vulnerabilities in it on older releases (clean on Go 1.26.10). `go.mod` pins a patched
toolchain, so `go build` fetches it. Re-scan when you upgrade.

The config file holds **no secrets**. Unknown settings are errors.

```json
{
  "baseUrl": "https://auth.example.com",
  "keyId": "k1",
  "apps": [{"id": "notes-demo", "name": "Notes Demo", "maxSubjects": 100, "onLimit": "waitlist",
            "attestationDays": 365, "origins": ["https://notes.example.com"]}],
  "smtp": {"addr": "smtp.example.com:587", "from": "noreply@example.com", "username": "mailer"}
}
```

| Environment variable | Holds |
|---|---|
| `GOLD_SIGNING_SEED` | 32 random bytes, base64. The attestation signing key |
| `GOLD_APP_SECRET_<ID>` | at least 32 random bytes, base64, per app (`notes-demo` → `GOLD_APP_SECRET_NOTES_DEMO`) |
| `GOLD_SMTP_PASSWORD` | the SMTP password, if `smtp.username` is set |

`baseUrl` must be `https`, except for localhost, because links carry secrets. It comes from configuration and never from a
request header, so a forged `Host` header cannot change the links. The server listens on `127.0.0.1` by default and does not
terminate TLS: put a TLS proxy in front. SMTP requires STARTTLS unless the mail server is on the same machine, and a failed
STARTTLS fails the send rather than falling back to plain text.

## Known limits

- **In-memory state.** A restart forgets unfinished confirmations (users just start again) **and app quotas and waitlists**, so
  an app can exceed its cap after a restart. Run one instance. A durable store comes in a later phase.
- **Email only.** Google sign-in, reply-email, Telegram, WhatsApp and SMS are not implemented. Configuring one is an error.
- **The rate limiter is per process** and fixed-window. Many source addresses can still fill its table, after which new
  clients get `429` until their windows expire.
- **No account recovery flow yet.** The server remembers only subject hashes.
- **Not reviewed externally.** See [SECURITY.md](../SECURITY.md).
