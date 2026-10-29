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
- **Build with the newest Go patch release.** `govulncheck` is clean on Go 1.26.10, but on older releases it reports many
  standard-library vulnerabilities in code the server runs (39 on Go 1.24.7, 10 on 1.25.13, at the time of writing). `go.mod`
  pins a patched toolchain so `go build` fetches it, and CI scans on the latest stable Go. Re-run `govulncheck` when you upgrade.
- CI runs the race detector, `golangci-lint` (including `gosec`), `govulncheck` and a short fuzz run.
- Parser bugs found by fuzzing are fixed and kept as regression tests.

## The confirmation server

`server` and `goldd serve` handle email addresses and issue signed attestations, so they get the most care:

- Opening a confirmation link never confirms. A button on the page does, because mail scanners open every link.
- Links and pickup secrets are stored hashed, compared in constant time, single use, and expire in 30 minutes.
- Requests are small, strictly parsed and rate limited per address and per client. Pending state is bounded.
- Addresses, tokens and pickup secrets are never logged. Error messages never echo input or print secrets.
- SMTP refuses to send in the clear to a remote server, never downgrades after a failed STARTTLS, and refuses addresses that could add headers or recipients before opening a connection.
- Each of these has a test, and each test was checked by deliberately breaking the code to confirm it fails.

**Run it behind a TLS proxy**, on one instance, with `GOLD_SIGNING_SEED` and the per-app secrets in the environment. Do not enable `-dev` in production: its inbox lists live links.

## Known limits

- Packets are **not encrypted** yet. The checksum is not a signature.
- A lost packet is a lost account unless the user confirmed an email or phone.
- Server state is in memory: a restart forgets unfinished confirmations **and app quotas**, so an app can exceed its cap afterwards. One instance only.
- Only email links are implemented. The rate limiter is per process and fixed-window.
