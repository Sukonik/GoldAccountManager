# Verification

How GoldAccountManager confirms an email or phone number as cheaply as possible, then remembers it in the packet.

The full explanation, with the cost ladder, is on the documentation site: [verification](verification.html).
The code is the Go package [`verify`](../verify).

In short:

1. **Confirm with the cheapest method the user already has**: verify later, Google, email (user-sent or magic link),
   Telegram contact share, WhatsApp (user first), and a paid SMS code only as a capped last resort.
2. **Confirm once, attest forever.** The server signs an attestation bound to one app and one packet. The packet carries it.
3. **No address or number inside.** The attestation subject is an HMAC under an app-specific secret.
4. **Passkeys after the first confirmation**, so later sign-ins send no codes.

There is no free outbound SMS. Prices and free allowances in the research notes came from third-party sources and must be
re-checked on each vendor's own page.
