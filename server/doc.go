// Package server is the confirmation service: it turns a confirmed email address
// into a signed attestation that the user keeps inside their packet.
//
// It is deliberately small. It stores no accounts and no passwords. For each
// confirmation it holds, for a short time, a hashed link token and a hashed
// pickup secret, and it remembers only a keyed hash of each confirmed address so
// it can enforce per-app quotas.
//
// The email flow, with who sees what:
//
//  1. The app (or the browser) calls POST /v1/apps/{app}/confirm/start with the
//     address and the packet id. The server emails a link and returns a
//     challenge id and a secret "pickup" value. Only the caller that started
//     the flow has the pickup value.
//  2. The user opens the link. It shows a page with a Confirm button. Opening
//     the link does nothing by itself, because email scanners open every link.
//  3. Pressing Confirm POSTs the token. The server checks it, applies the app's
//     quota, and signs an attestation for that packet.
//  4. The caller polls POST /v1/apps/{app}/confirm/pickup with the challenge id
//     and the pickup value, and receives the attestation once.
//
// Everything that can be abused is limited: requests are small and strictly
// parsed, mail is rate limited per address and per client, pending state is
// bounded, and secrets and addresses are never logged.
package server
