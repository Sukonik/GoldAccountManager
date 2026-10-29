# Security

GoldAccountManager is in early development (Phase 0). It has not had an external security review. Do not use it to protect
real private data yet.

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability** on
<https://github.com/Sukonik/GoldAccountManager/security>. Do not open a public issue for a vulnerability.

Include what you found, how to reproduce it, and which version or commit. You should get a first reply within a few days.

## What we already do

- Parsing is strict: size limits, known fields only, bounded values, case-sensitive names.
- Random identifiers come from `crypto/rand`. Secrets are compared in constant time.
- `govulncheck` reports no issues in the `packet` and `verify` libraries or `goldd` on any Go version tried. The docs build
  tool needs a current Go release (it is clean on Go 1.26.9).
- CI runs the race detector, `golangci-lint` (including `gosec`), `govulncheck` and a short fuzz run.
- Parser bugs found by fuzzing are fixed and kept as regression tests.

## Known limits

- Packets are **not encrypted** yet. The checksum is not a signature.
- A lost packet is a lost account unless the user confirmed an email or phone.
- There is no rate limiting or server yet. Confirmation channels in this release are for demos.
