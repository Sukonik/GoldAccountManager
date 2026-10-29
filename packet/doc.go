// Package packet implements the Gold packet: a portable, user-owned account
// file. A packet is plain JSON that carries an app's data (the payload), its
// identity and revision history, and any server-signed attestations.
//
// The design descends from the packet format in Sukonik/payout-lab (JavaScript,
// MPL-2.0). Identity labels, lineage-based revision comparison, whitelisted
// parsing and the canonical-JSON checksum are compatible with that format, so a
// checksum computed here matches one computed there for the same data.
//
// Parsing never executes content. Every envelope field is whitelisted,
// type-checked and bounded before anything reaches the application, and the
// payload is checked for size and depth. The checksum detects accidental
// damage only. It is not a signature: anyone can edit a file and recompute it.
// Anything a server must trust (a verified phone, a paid plan) belongs in a
// signed attestation, see package verify.
package packet
