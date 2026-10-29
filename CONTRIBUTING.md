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
```

If you changed anything under `site/`, rebuild the docs with `go run ./cmd/sitegen` and commit `docs/` too. CI fails when
`docs/` is out of date.

## Rules

- **No new dependencies** without a written reason in the pull request.
- **Test the hostile case**, not only the happy one. Parser changes need a fuzz seed or a regression test.
- **Cross-language checksums** must keep matching Payout Lab's JavaScript. See `packet/canonical_test.go`.
- **Docs examples are real.** Example files in `site/examples/` are checked by tests. Go snippets live in `Example` tests.
- **Never copy AGPL code** (for example from Zitadel). Read it for ideas only.
- Follow the style in the existing code: early returns, errors with context, `t.Parallel()` on independent tests.

## Releasing a new site version

1. Edit `site/VERSION` and add an entry to `site/versions.json`.
2. Run `go run ./cmd/sitegen -snapshot vX.Y` to write the latest site and a preserved copy under `docs/vX.Y/`.
3. Commit `docs/`. Preserved folders are never edited afterwards.
