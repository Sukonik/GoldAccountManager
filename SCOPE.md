# Scope: what we build first

This page is the decision. [FEATURES.md](FEATURES.md) is the long wishlist, and [PLAN.md](PLAN.md) is the phase plan. If they disagree with this page, this page wins.

## Requirements (from the owner)

1. **User accounts for any of my apps.** Many apps, one system.
2. **Scale at low cost.** Cheap to start, cheap to grow.
3. **Free versions with limited user counts** at first, then raise the limit or charge.
4. Simple to demo, with a clean UI.

## The approach

**A self-hosted Go service: a single binary with SQLite to start, Postgres when you outgrow it.** Think "Firebase Auth that you run yourself."

Why this fits the requirements:

| Requirement | How |
|---|---|
| Any app | Each app is a row in an `apps` table. Adding an app takes one command, not a new deployment |
| Low-cost scale | One small server (a few dollars a month) with SQLite handles a lot of small apps. The cost is flat, not per active user |
| Free tier with user limits | **Per-app user quotas are a built-in feature** (below) |
| Easy demo | `goldd demo` seeds two demo apps and prints a login link |

Costs to watch are not hosting. They are **SMS** (paid per message, and abused by fraud bots) and **email** (cheap but needs a sending provider). So v0.1 uses email magic links and Google login only. SMS stays off by default and, when added, has a hard spending cap.

Honest trade-offs against Firebase:
- Firebase is faster to start and Google runs it for you. Gold is cheaper at scale, you own the data, and you can add features like personas and offline grants. In return, you are responsible for uptime, backups and security patches.
- Authentication is high-risk code. We reduce that risk by keeping v0.1 small, avoiding stored passwords at first (magic links and Google login only), and testing the security-critical paths heavily. Verify current Firebase pricing yourself before deciding how much cost matters.

## Quotas: the free-tier feature

Every app has a plan, and every plan has limits that Gold enforces:

| Setting | Meaning | Example |
|---|---|---|
| `max_users` | Hard cap on accounts for this app | 100 on Free |
| `max_monthly_active` | Optional soft cap on active users | 50 |
| `sms_budget` | Monthly spend or message cap (later) | 0 on Free |
| `on_limit` | `block_signups` (default), `waitlist`, or `notify_only` | `waitlist` |

- Existing users are never locked out when the cap is hit. Only new sign-ups are affected.
- The sign-up screen shows a plain "This app is full, join the waitlist" message instead of an error.
- Raising a limit is one config change or one admin button. Later, it can follow a billing plan.
- Quotas belong to the **app**, not the end user. This is the developer-facing side of billing. End-user billing is a later feature.

## Version 0.1: the only things we build

1. **Apps:** create and configure apps, each with an ID, allowed redirect URLs, plan and quotas.
2. **Sign-in:** email magic link and Google login.
3. **Anonymous then linked:** start as a guest and attach a real login later, so no data is lost.
4. **One account, many apps:** a user signs up once and opens a second app with a one-tap "Continue as…" (standard OIDC code + PKCE underneath).
5. **Purpose per app:** Work / Personal / Utility, saved as a field for now.
6. **Sessions:** secure cookies and tokens, with rotation and revocation.
7. **Roles:** a simple role field per app, checked in the app's own code.
8. **Quotas:** as above.
9. **Admin page:** apps, users, quotas and sessions, with clean UI.
10. **Audit table:** an append-only log of sign-ins and admin actions.
11. **Demo mode:** seeded data and a dev inbox page, so there is no email provider to set up.

## Not in v0.1 (parked in FEATURES.md)

SMS codes, passkeys, TOTP, device recognition, field encryption, media, billing and Stripe, the offline legal mode, SAML and enterprise SSO, organizations and teams, Casbin and Keto adapters, hash-chained audit, and Postgres. Each is a separate later step. Nothing in 0.1 should block any of them.

## Rules for the build

- Standard library first. Extra dependencies need a written reason.
- Every table that holds users carries an `app_id`, so quotas and multi-app work from day one.
- Interfaces for `Store`, `Mailer` and later `SMSSender`, so SQLite-to-Postgres and Stripe-later are not rewrites.
- Take ideas from Kratos, Keycloak, SuperTokens and Casdoor (links in FEATURES.md). Never copy AGPL code (Zitadel).

## Done means

A stranger can clone the repo, run `goldd demo`, sign in to Demo App A with a magic link, open Demo App B with one click, hit the 100-user cap in a test app and see the waitlist message, and see all of it in the admin page. That takes under five minutes.

## Next step

Phase 0 from [PLAN.md](PLAN.md): Go module, CI, migrations and an empty skeleton with passing tests. Then build the list above in order.

## Still open

1. Is **Google login plus email magic link** enough for v0.1, or does an app need something else on day one?
2. Do all your apps sit under one parent domain (simpler) or on unrelated domains?
3. Which hosting do you have in mind (a VPS, Fly.io, a home server)? It only affects the demo and Docker setup.
