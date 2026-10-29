# Contributing

Thanks for helping. This project is small on purpose: standard library only, strict parsing, and every claim in the docs
backed by a test or a link.

## Set up

Go 1.24 or newer builds the libraries and `goldd`. Use a **current Go release** (1.26.9 or newer at the time of writing) for
`cmd/sitegen`: `govulncheck` reports standard-library issues in `html/template` and `os` on older releases. Install the two
checkers once:

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
