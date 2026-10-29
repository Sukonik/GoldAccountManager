# Contributing

Thanks for helping. This project is small on purpose: standard library only, strict parsing, and every claim in the docs
backed by a test or a link.

## Set up

`go.mod` pins a patched Go toolchain (`toolchain go1.26.10`), and `go` fetches it automatically. That is deliberate: the
confirmation server is a network service, and `govulncheck` reports dozens of standard-library vulnerabilities in code it
runs on older releases. When `govulncheck` reports something fixed in a newer patch release, raise the `toolchain` line.
The `packet` and `verify` libraries themselves build with Go 1.24+. Install the two checkers once:

```bash
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
```

## Before you push

```bash
golangci-lint fmt ./...
go vet ./...
go test -race ./...
golangci-lint run ./...
govulncheck ./...
go run ./cmd/sitegen -check
node --test site/tests/packet.test.mjs     # browser reader vs the shared Go cases
```

If you changed anything under `site/`, rebuild with `go run ./cmd/sitegen` and commit `docs/` and the README too. CI fails
when either is out of date.

## Two readers, one format

`packet/` (Go) is the reference reader. `site/assets/gold-packet.js` is a second one for browsers. Both must give the same
answer on every case in `packet/testdata/parity.json`. If you change a parsing rule, change **both** readers and add a case
that only that rule can fail: the Go test is `packet/parity_test.go`, the JavaScript test is `site/tests/packet.test.mjs`.
When you add a case, break the rule on purpose in each reader to confirm a test notices. Several early cases passed for the
wrong reason, and this is how that was found.

The same discipline applies to the server: for every security property, break the code on purpose (drop a check, skip a header,
widen a limit) and confirm a test fails. If none does, the test is passing for the wrong reason. Examples found this way: a
fake SMTP server that served only one connection, so every later attempt "failed" by timeout, and a test that compared whole
outputs while one fixed value hid among random ones.

Before releasing a site version, also run the browser check by hand (needs Playwright):
`go run ./cmd/sitegen && node site/tests/e2e-try.mjs`.

## Rules

- **No new dependencies** without a written reason in the pull request.
- **Test the hostile case**, not only the happy one. Parser changes need a fuzz seed or a regression test.
- **Cross-language checksums** must keep matching Payout Lab's JavaScript. See `packet/canonical_test.go`.
- **Docs examples are real.** Example files in `site/examples/` are checked by tests. Go snippets live in `Example` tests.
- **Never copy AGPL code** (for example from Zitadel). Read it for ideas only.
- Follow the style in the existing code: early returns, errors with context, `t.Parallel()` on independent tests.

## Releasing a new site version

```bash
go run ./cmd/sitegen release -version 0.2.0 -name "Short name" -summary "One sentence."
```

This records the version, rebuilds the latest site, writes a preserved copy under `docs/v0.2/`, and regenerates the version
and page tables in the README. Commit the result. Preserved folders are never edited afterwards, and the command refuses to
overwrite one. You can also run it from GitHub (Actions, "Release site version"), which pushes a `release/vX.Y.Z` branch.
