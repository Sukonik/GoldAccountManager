# GoldAccountManager Design

GoldAccountManager (GAM) gives an app accounts in one of two modes behind the same identity format:

- **Packet mode (serverless):** the user carries a signed JSON file. The app verifies it locally. No account server.
- **Server mode:** the same packet is the identity, and a small Go service adds a shared directory, roles, sessions and admin tools.

An app picks the mode that matches its shape. A user can move from packet mode to server mode later without a new identity.

## Why two modes

Some apps are single-player. A weather app, a dividend calculator or a planner only needs the user's own settings. A server for accounts is pure cost there.

Other apps need a shared pool of people. A dating app has to show person A to person B, record mutual interest, deliver chat and handle block and report. Something has to hold the public parts of that shared state.

GAM supports both so tools like ClearSky and Payout Lab can stay serverless while apps like Pasta use a thin server.

## The packet

A packet is a JSON file with the user's public identity, profile and settings, signed with an Ed25519 key.

```json
{
  "v": 1,
  "id": "<base64url public key>",
  "public_key": "<base64url public key>",
  "created_at": "2026-11-14T17:00:00Z",
  "updated_at": "2026-11-14T17:00:00Z",
  "profile":  { "name": "Nathan" },
  "settings": { "units": "imperial" },
  "signature": "<base64url signature>"
}
```

Design choices:

- **The id is the public key.** No usernames, no registry, no collisions.
- **The private key is stored separately from the packet.** The packet can be shared or backed up freely. The key stays on the device (Keychain, Keystore, WebCrypto non-extractable key).
- **Any edit means re-signing.** Tampering with a packet without the key breaks verification.
- **A valid signature proves key control, not truth.** Profile claims are still just claims.
- **Challenge-response proves the holder is present.** An app or server sends a nonce, the holder signs it. Challenge signatures are domain-separated from packet signatures.

### Canonicalization

Go's `encoding/json` sorts map keys, so signing is deterministic within Go. Clients in other languages must produce identical bytes, so a v1 non-Go client should use RFC 8785 (JCS). Locking this down is an open item below.

### Where the packet lives

On the user's own device, or in storage they already have, such as Google Drive. The user brings their own storage, so the developer pays nothing for it.

### Loss and recovery

Losing the device means losing the key. Options, from simplest to strongest:

1. Export the 32 byte seed as a recovery phrase or file.
2. Back the packet and an encrypted seed up to the user's Drive.
3. Social or multi-device recovery, as a later addition.

Packet mode has no password reset, so recovery has to be offered up front.

## Server mode

Registration, challenge and login endpoints are implemented. A client registers by posting its packet, then logs in by signing a one-time nonce.

| Endpoint | Purpose |
| --- | --- |
| `POST /register` | Verify and store the account. Only the public profile is stored. Settings stay with the user. |
| `POST /challenge` | Issue a single-use nonce that expires in 2 minutes. |
| `POST /login` | Verify the signed nonce and issue a session token. |

Other behavior:

- No passwords exist anywhere, so there is nothing to leak or reset.
- Nonces are single use, even on a failed attempt.
- Roles (`user`, `admin`) live on the server account, never in the packet, because the packet is user-controlled.
- `Store` is an interface. The memory store is for development. Production needs a real database.

## Security notes and limits

- A packet alone does not stop someone copying a stolen device's key file. Device storage and optional passcode protection matter.
- Sybil attacks and fake profiles are not solved by keys, since anyone can make a key. A shared-pool app needs rate limits, proof of work, verification or invitations. This is a server-mode concern.
- Session tokens are in memory in this skeleton. Persist and rotate them for production.
- Registration is open. Add rate limiting before exposing it.

## Servers vs serverless for dating apps

This design came out of a discussion about whether a dating app can run with no server at all.

Findings:

- **It is technically possible.** Projects such as OpenDate, YouCupid (both on Nostr) and the academic DODA design do identity, discovery, matching and encrypted chat peer to peer or over public relays. A user's identity there is just a key pair, which matches the packet idea.
- **The hard parts are not cryptographic.** Swiping needs a large shared pool, phones are not always online, and with nobody in charge, spam and fake profiles are hard to police.
- **Cold start is the real risk.** Nobody joins an empty pool, so a launch usually has to seed one city at a time.
- **A middle road is practical.** The packet is the identity and holds private settings. A thin server holds only public profiles and the match graph.

Recommendation: ship Pasta on server mode (packet identity plus a thin server), keep packet mode for single-player tools, and revisit relay-based discovery later if the thin server proves unnecessary. Tracked in the issue on this topic.

## Open items

- Pin the canonical JSON format (JCS) and publish test vectors.
- Add packet export and import helpers for web and mobile clients.
- Persistent `Store` implementation (SQLite first).
- Session persistence, expiry sweeps and revocation.
- Registration rate limiting and an abuse hook.
- Admin tools: list, suspend, change role.
- Packet to server upgrade flow (register an existing packet).
- Recovery options beyond seed export.
