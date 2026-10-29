// Package verify turns a confirmed email, phone or device into a signed
// attestation that rides inside a packet.
//
// Three ideas make confirmation cheap and private:
//
//   - Confirm once, attest forever. After any channel succeeds, the server
//     signs a short statement bound to one packet in one app. Later, no code
//     needs to be sent.
//   - Subjects are keyed hashes. An attestation never contains the email
//     address or phone number. Its subject is an HMAC under an app-specific
//     secret, so the same person in two apps has two unrelated subjects.
//   - Channels are interchangeable. Anything that can prove control of a
//     target (a magic link, a reply email, a Telegram contact share, a paid
//     SMS) implements Channel, and the app chooses which to offer. See
//     docs/verification.md for the ladder, cheapest first.
package verify
