# GoldAccountManager 👑

A plug-and-play account management toolkit written in Go. Drop in authentication, user profiles, roles, sessions, and admin tools, then self-host or customize it to fit your product. Open source, dependency-light, and built to be forked, so you own your user data instead of renting it.

> **Status: early planning.** The design is in [PLAN.md](PLAN.md). Nothing below is released yet, and the API sketches are targets, not promises.

## Why GoldAccountManager

- **Two ways to use it.** Import it as a Go library, or run the standalone `goldd` server.
- **Dependency-light.** Built on the standard library, with a minimal, justified set of extras.
- **Secure by default.** Argon2id password hashing, hashed tokens at rest, CSRF protection, rate limiting, and secure cookies from day one.
- **You own your data.** Plain SQL schema, full export and import, and migration from other hash formats.
- **Batteries included.** An embedded admin UI, an audit log, and RBAC ship in the box.
- **Pluggable.** Swap the store, mailer, rate limiter, or hasher by implementing a small interface.

## Features

| Area | Planned capabilities |
|---|---|
| Authentication | Email and password, email verification, password reset, TOTP, passkeys (WebAuthn), OAuth2/OIDC |
| Sessions | Opaque tokens, rotation, device list, sign out everywhere, sliding and absolute expiry |
| Profiles | CRUD with custom fields |
| Roles and permissions | Database-backed RBAC with a `Can()` check and middleware |
| Admin | Embedded UI for users, roles, sessions, and audit log; impersonation with guardrails |
| Audit | Append-only log of auth and admin actions |
| Storage | SQLite (default), Postgres, or your own `Store` |
| Operations | Single static binary, Docker image, structured logs |

## Quick look (target API)

Embedded as a library:

```go
am, err := goldaccountmanager.New(goldaccountmanager.Config{
    Store: sqlite.Open("accounts.db"),
})
if err != nil {
    log.Fatal(err)
}

mux := http.NewServeMux()
mux.Handle("/auth/", am.AuthHandler())
mux.Handle("/admin/", am.RequirePermission("admin:access", am.AdminHandler()))
mux.Handle("/api/refunds", am.RequirePermission("invoice:refund", refundHandler))

log.Fatal(http.ListenAndServe(":8080", mux))
```

Standalone:

```bash
goldd serve --db accounts.db --addr :8080
```

## Roadmap

1. **Foundations:** module, CI, config, migrations
2. **Core auth (MVP):** register, login, sessions, verification, reset, audit log
3. **Profiles, roles, admin UI**
4. **Hardening and extras:** TOTP, passkeys, Postgres, OIDC, API keys
5. **Release:** docs, Docker image, security review, `v0.1.0`

Full detail, architecture, and open questions are in [PLAN.md](PLAN.md). The feature catalog, app presets (Work / Leisure / Utility), and links to the open-source projects we learn from (Keycloak, Ory Kratos, Zitadel, Casdoor, SuperTokens, Authentik) are in [FEATURES.md](FEATURES.md).

## Contributing

Contributions are welcome once the foundations land. In the meantime, feedback on [PLAN.md](PLAN.md) is the most useful thing you can give: open an issue with questions, objections, or missing requirements. Security issues should be reported privately, and a `SECURITY.md` will describe how.

## License

Licensed under the [Mozilla Public License 2.0](LICENSE).
