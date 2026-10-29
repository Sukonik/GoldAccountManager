# GoldAccountManager: Build Plan

**Goal:** a plug-and-play account management toolkit in Go. Drop it in for auth, profiles, roles, sessions, and admin tools. Self-host it or embed it. Dependency-light, forkable, and you own the data.

**Start here:** [SCOPE.md](SCOPE.md) is the current decision on what to build first and overrides the rest if they disagree.

**See also:** [FEATURES.md](FEATURES.md) for the feature catalog, app presets, and per-feature upstream references.

**Status:** planning. Nothing is implemented yet. Everything below is a proposal to react to.

## Principles

1. **Two ways to use it.** An importable Go library (`import "github.com/sukonik/goldaccountmanager"`) and a standalone server binary built on that library.
2. **Standard library first.** `net/http`, `database/sql`, `log/slog`, `crypto/*`. Allowed extra dependencies: `golang.org/x/crypto` (argon2id) and one pure-Go SQLite driver. Every new dependency needs a written justification.
3. **Secure by default.** Argon2id, constant-time comparisons, hashed session and reset tokens at rest, CSRF protection, rate limiting, and secure cookie flags on from the start.
4. **Storage behind interfaces.** SQLite is the default and Postgres comes second. Users supply their own store by implementing small interfaces.
5. **You own your data.** Plain SQL schema, full export and import, no lock-in.

## Unique resources (differentiators)

These are what should make this more than another auth library.

| Resource | What it is | Why it matters |
|---|---|---|
| **Single-binary mode** | `goldd` serves the API, admin UI (embedded via `embed`), and migrations from one static binary with SQLite | Zero-ops self-hosting |
| **Embeddable admin UI** | Mountable `http.Handler` for user, role, and session management, themeable with plain CSS variables | Admin tools with no separate frontend project |
| **Policy-as-data RBAC** | Roles and permissions in the DB plus a `Can(user, "invoice:refund")` check, with optional per-resource scopes | Simple now, extensible to ABAC later |
| **Audit log by default** | Append-only record of every auth and admin action, with actor, IP, and user agent | Compliance and debugging without extra work |
| **Pluggable everything** | Interfaces for `Store`, `Mailer`, `RateLimiter`, `PasswordHasher`, `Clock` | Testable and replaceable |
| **Data portability** | `goldd export` and `goldd import` (JSON/NDJSON), including password-hash migration from bcrypt and others | "Own your data" made literal |
| **Impersonation with guardrails** | Admin "act as user" with a visible banner, a time limit, and audit entries | A feature support teams want and most libraries skip |
| **Session hygiene** | Device list, "sign out everywhere", sliding and absolute expiry, and anomaly flags | Strong default account security |
| **Passkeys (WebAuthn) and TOTP** | Phase 3 add-ons behind the same `Authenticator` interface | Modern login without lock-in |

## Prior art: what to learn from existing projects

These are mostly standalone identity *services*. GoldAccountManager is aimed at being an embeddable Go library with an optional server, so we use them as references, not as dependencies. Descriptions are from memory and should be re-checked against each project's current docs and license before we rely on them.

| Project | Stack | What to borrow | What to avoid |
|---|---|---|---|
| **Ory Kratos** | Go | Closest relative. Headless design and self-service *flows* (registration, login, recovery, verification, settings) exposed as API state machines. Identity traits defined by JSON Schema. | Its operational split into several Ory services. We want one binary or one import. |
| **Zitadel** | Go | Event-sourced design, so the audit trail falls out of the data model. Organization-level multi-tenancy. | Its complexity, and its license (AGPL in recent versions): read for ideas only, never copy code into an MPL-2.0 project. |
| **Casdoor** | Go | A UI-first admin experience, a broad catalog of social login providers, and Casbin-based authorization. | Config sprawl. We keep policy as simple data. |
| **SuperTokens** | Java core, SDKs in several languages | The "recipe" and override pattern for customizing behavior. Refresh-token rotation with token-theft detection. | The separate core service. We want it in-process. |
| **Authentik** | Python | The flows-and-stages model for composable login journeys. Policy bindings. | Runtime weight, and a stack that is not Go. |
| **Keycloak** | Java | The reference for realms, clients, and protocol coverage (OIDC, SAML). A mature admin console to study for UX. | Heavy footprint, a steep learning curve, and being a full IAM platform. |

### How this feeds the plan

- **Phase 1 sessions:** adopt refresh-token rotation with reuse detection (SuperTokens).
- **Phase 1-2 API shape:** model login, registration, and recovery as explicit flows (Kratos, Authentik) so new steps like MFA slot in without breaking clients.
- **Phase 2 profiles:** consider JSON Schema validation for custom profile fields (Kratos).
- **Audit log:** keep it append-only now, and decide whether to go event-sourced (Zitadel) before the schema is locked in.
- **Phase 3 OIDC login:** copy Casdoor's idea of a provider catalog, behind one small `Provider` interface.
- **Positioning:** our gap versus all of them is "import it as a library, one binary, SQLite by default, no separate service to operate."

## Architecture

```
goldaccountmanager/
├── cmd/goldd/          # standalone server binary
├── account/            # core domain: User, Profile, Credential
├── auth/               # password, token, TOTP, passkey authenticators
├── session/            # session issuing, rotation, revocation
├── rbac/               # roles, permissions, Can()
├── audit/              # append-only event log
├── store/              # Store interfaces
│   ├── sqlite/
│   └── postgres/
├── httpapi/            # REST handlers + middleware
├── admin/              # embedded admin UI (embed.FS)
├── mail/               # Mailer interface + SMTP + log-only dev mailer
├── migrations/         # versioned SQL
├── internal/           # crypto helpers, clock, ids
├── examples/           # minimal embed, full server, custom store
└── docs/
```

## Phases

### Phase 0: Foundations
- [ ] `go mod init`, CI (vet, test, race, staticcheck), `golangci-lint` config
- [ ] `CONTRIBUTING.md`, `SECURITY.md`, issue and PR templates
- [ ] Config loading (env + file), structured logging with `slog`
- [ ] Migration runner and the first schema (`users`, `credentials`, `sessions`, `audit_log`)

**Exit:** `go test ./...` is green in CI on an empty but wired-up skeleton.

> **Core offer (see [FEATURES.md](FEATURES.md)):** one account across many first-party apps, with a user-chosen purpose (Work / Personal / Utility). Phase 1 therefore includes a thin first-party OIDC provider (code + PKCE, consent screen, pairwise subject IDs) and a two-app demo, not just local login.

### Phase 1: Core auth (MVP)
- [ ] Register, login, logout with email and password (argon2id, tunable params)
- [ ] Sessions: opaque random tokens, stored hashed, cookie-based, rotation on login
- [ ] Email verification and password reset (single-use, expiring tokens)
- [ ] Rate limiting and lockout (in-memory limiter, interface for Redis later)
- [ ] CSRF protection and secure cookie defaults
- [ ] SQLite store
- [ ] Audit log wired into every auth event

**Exit:** a sample app can sign up, verify, log in, reset a password, and log out. Security tests cover the common failure modes (token reuse, timing, enumeration).

### Phase 2: Profiles, roles, admin
- [ ] Profile CRUD with extensible custom fields (JSON column plus typed accessors)
- [ ] RBAC: roles, permissions, assignment, `Can()` middleware
- [ ] Admin API and embedded admin UI: search users, edit, disable, assign roles, view audit log
- [ ] Session management: list devices, revoke one or all
- [ ] Impersonation with guardrails

**Exit:** an admin can run the whole user lifecycle from the UI.

### Phase 3: Hardening and extras
- [ ] TOTP and recovery codes
- [ ] Passkeys (WebAuthn)
- [ ] Postgres store
- [ ] OAuth2 / OIDC login (Google, GitHub) via a small provider interface
- [ ] API keys and service accounts
- [ ] Export / import tooling and legacy hash migration

**Exit:** feature parity with the commonly needed parts of hosted auth products.

### Phase 4: Release
- [ ] Docs site (quickstart, embedding guide, threat model, upgrade guide)
- [ ] Docker image and a `docker compose` example
- [ ] External security review or at least a structured self-audit against the OWASP ASVS L2 checklist
- [ ] Tag `v0.1.0`, then follow semver

## Security checklist (applies to every phase)

- Never store plaintext tokens, store hashes
- Generic error messages on login and reset (no user enumeration)
- Constant-time comparisons for secrets
- Session fixation prevented by rotating IDs on privilege change
- Dependency scanning (`govulncheck`) in CI
- A documented threat model in `docs/threat-model.md`

## Testing strategy

- Unit tests per package, table-driven
- Store contract tests that every `Store` implementation must pass
- Integration tests with `httptest` against an in-memory SQLite
- Fuzz tests for token parsing and input validation
- Injectable `Clock` so expiry logic is tested without sleeping

## Open questions

1. **Module path and name.** `github.com/sukonik/goldaccountmanager`, or something shorter?
2. **Admin UI approach.** Server-rendered templates with htmx (fewer moving parts) or a small SPA?
3. **Multi-tenancy.** Is it in scope for v1, or is one user pool per deployment enough?
4. **API style.** REST only, or also gRPC / GraphQL?
5. **Minimum Go version.** Proposing the latest two releases.
6. **The "unique resources" list.** Anything from the earlier discussion that should be added to or replace the table above?

## Next step

Once the open questions are settled, start **Phase 0** and build only the skeleton and CI, so there is a green baseline to work from.
