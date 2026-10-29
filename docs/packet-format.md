# Gold packet format (schema version 1)

A **packet** is the portable copy of one user's account in one app: a single plain JSON file, extension `.gold`.
Opening a packet restores the app's data without sign-up or upload.

This is the normative description. The reference implementation is the Go package [`packet`](../packet), and
[`site/examples/`](../site/examples) holds real files that tests keep valid. The format descends from Payout Lab's
[packet format](https://github.com/Sukonik/payout-lab/blob/main/docs/packet-format.md).

> **A packet is not encrypted.** Keep it private. The checksum catches accidental damage and is **not** a signature:
> anyone can edit a file and recompute it. Anything a server must trust belongs in a signed attestation.

## Envelope

| Field | Type | Rules |
|---|---|---|
| `format` | `"gold-packet"` | Must match exactly |
| `schemaVersion` | integer | `1`. A higher number is rejected with `future_version`, never partly read |
| `appId` | string | `^[a-z0-9][a-z0-9-]{1,39}$`. An app passes its own id when opening, so a packet only opens in the app it was made for |
| `packetId` | string | `^pk_[0-9a-z]{8,32}$`. New ids are `pk_` + 13 random base-32 characters (65 bits). A label, not a secret |
| `name` | string | Control characters removed, at most 80 characters, defaults to "My account" |
| `revisionId` | string | `^rv_[0-9a-z]{8,32}$`. Changes on every save |
| `parentRevisionId` | string or `null` | The revision this one was made from |
| `lineage` | list of revision ids | Recent revisions, oldest first, ending with `revisionId`. At most 200. An empty or truncated list is repaired |
| `createdAt`, `savedAt` | string | ISO 8601 / RFC 3339. Written as UTC with milliseconds |
| `app` | `{name, version}` | Which build wrote the file. Version is at most 20 characters |
| `origin` | `{packetId, revisionId, relation}` | Present only on a separate copy. `relation` is always `"copy"` |
| `payload` | object | The app's data. At most 4 MiB and 32 levels deep. Validated by an app-supplied function |
| `attestations` | list | At most 8. See below |
| `checksum` | `{alg, value}` | `alg` is `"sha-256"`. `value` is the lowercase hex SHA-256 of the canonical JSON of every other field |

Field names are **case-sensitive**. A name that differs from a known name only by case (`AppId`) is rejected with
`bad_value`, because other readers do not match case-insensitively and two readers disagreeing about one file is how
smuggling attacks work.

## Attestation

| Field | Rules |
|---|---|
| `kind` | `email`, `phone` or `device` |
| `method` | `google`, `email-link`, `email-reply`, `telegram`, `whatsapp`, `sms` or `passkey` |
| `subject` | 64 lowercase hex characters: HMAC-SHA-256 under an app-specific secret. **Never the address or number itself** |
| `issuedAt`, `expiresAt` | ISO 8601. `expiresAt` is optional |
| `keyId` | `^[0-9a-z-]{1,32}$`. Names the server key, so keys can be rotated |
| `signature` | base64url (no padding) Ed25519 signature |

The signature covers the canonical JSON of `{domain, appId, packetId, kind, method, subject, issuedAt, expiresAt, keyId}`
where `domain` is `"gold-attestation-v1"`. Because `appId` and `packetId` are signed, an attestation cannot be moved to
another packet or app. Parsing validates only the *shape*. Verifying signatures needs the server's public key: see
package [`verify`](../verify).

## Canonical JSON and the checksum

Canonical JSON has object keys sorted, no whitespace, strings escaped as `JSON.stringify` does (only `"`, `\` and control
characters), and numbers written as ECMAScript's `Number.prototype.toString` writes them. It is identical to Payout Lab's
`canonicalJson`, and the Go tests check checksums against vectors produced by that JavaScript.

## Parsing rules

1. Reject files over 5 MiB. Ignore a leading byte-order mark.
2. Reject non-JSON, non-objects and any `format` other than `gold-packet`.
3. Check `schemaVersion` before anything else.
4. Reject field names that differ from known names only by case.
5. Rebuild the packet from known fields only. Unknown fields are dropped.
6. Validate ids, dates, names and attestations against the patterns above.
7. Check the payload: an object, within the size and depth limits, then through the app's validator.
8. Compare the checksum. A mismatch or a missing checksum is a **warning**, not an error: the app should show it.

Error codes: `not_packet`, `bad_json`, `bad_type`, `bad_version`, `future_version`, `too_large`, `too_many`, `bad_value`,
`app_mismatch`, `bad_payload`. Warning codes: `checksum_mismatch`, `no_checksum`.

## Comparing copies

| Relation | Rule |
|---|---|
| `different-packet` | Different `packetId` |
| `identical` | Same `revisionId` |
| `incoming-newer` | The incoming lineage contains the local revision |
| `incoming-older` | The local lineage contains the incoming revision |
| `diverged` | None of the above: both changed. Offer a separate copy, never last-write-wins |

A **separate copy** gets a new `packetId`, records `origin`, and drops attestations (they were issued for the original
packet id and would not verify).
