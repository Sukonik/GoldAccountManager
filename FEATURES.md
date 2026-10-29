# GoldAccountManager: Feature Plan

Companion to [PLAN.md](PLAN.md). PLAN.md covers phases and architecture. This document covers **what features we need and why**, driven by the apps this will power.

Upstream references are linked throughout. Descriptions of other projects are from memory, so re-verify against each repo before depending on a detail.

## Reference projects

| Project | Repo | License (verify) | Use |
|---|---|---|---|
| Keycloak | <https://github.com/keycloak/keycloak> | Apache-2.0 | Realms, admin UX, protocol coverage, required actions |
| Ory Kratos | <https://github.com/ory/kratos> | Apache-2.0 | Self-service flows, identity schemas, session model |
| Ory Hydra / Keto | <https://github.com/ory/hydra>, <https://github.com/ory/keto> | Apache-2.0 | OAuth2/OIDC provider, relationship-based permissions |
| Zitadel | <https://github.com/zitadel/zitadel> | AGPL-3.0 in recent versions | Event sourcing, organizations, audit. **Ideas only, never copy code.** |
| Casdoor | <https://github.com/casdoor/casdoor> | Apache-2.0 | Provider catalog, UI-first admin |
| Casbin | <https://github.com/casbin/casbin> | Apache-2.0 | Policy engine for authorization |
| SuperTokens | <https://github.com/supertokens/supertokens-core> | Apache-2.0 core | Refresh rotation and theft detection, recipes/overrides |
| Authentik | <https://github.com/goauthentik/authentik> | MIT (open core, verify) | Flows and stages, policies |
| go-webauthn | <https://github.com/go-webauthn/webauthn> | BSD-3 | Passkey implementation we would use |
| pquerna/otp | <https://github.com/pquerna/otp> | Apache-2.0 | TOTP implementation we would use |

**License rule:** GoldAccountManager is MPL-2.0. Apache, MIT and BSD code can be used with attribution. AGPL code (Zitadel) must not be copied. Read its design, then write our own.

> **Superseded:** the owner has decided that apps must **not** share accounts (see [SCOPE.md](SCOPE.md), Decision 1). Each app is an isolated user pool. The "sign up once" section below is kept only as a record of the idea and as a possible future opt-in. Ignore its OIDC-provider and pairwise-ID requirements for now.

## Core offer: sign up once, use every app (superseded)

**The user creates one Gold account and never fills in a sign-up form again.** Opening a second app is a one-tap "Continue as Sam" screen, not a new registration. This is the product. Everything else in this document serves it.

### How it works

1. **One identity, many apps.** A central account holds credentials (passkey, magic link, phone, password) and a single sign-on session. Each of your apps is a registered *client* of it. This is the Keycloak realm-and-client model (<https://github.com/keycloak/keycloak>) at a much smaller scale.
2. **Lazy, per-app profiles.** A new app only asks for what it needs, at the moment it needs it (progressive profiling). Keycloak's *required actions* and Kratos settings flows are the reference (<https://github.com/ory/kratos>). The legal app might ask for a firm name. The utility app asks for nothing.
3. **"What are you using this for?"** On first use of an app, or once at account creation, the user picks a purpose: **Work**, **Personal**, or **Utility**. Each purpose is a **persona**: its own profile, display name, visibility settings, and (for Work) organization membership. Personas are chosen by the user but constrained by the app, see rule 2 below.
4. **Pairwise identifiers by default.** Each app sees a different, stable subject ID for the same person (OIDC "pairwise subject identifiers"). The dating app and the legal software cannot correlate users by ID, and the user can see and revoke which apps are connected. Linking personas is something the user opts into, never a default.

### Two rules that keep this safe

1. **A shared login must not become a shared blast radius.** Signing in to the account is not enough for high-stakes apps. Each app declares a minimum assurance level (the preset in the next section), and the account steps up when the user enters it: for example a passkey or TOTP for the legal app, even if the user normally signs in with a magic link. This is Kratos's `aal1`/`aal2` idea (<https://github.com/ory/kratos>) and Keycloak's step-up authentication (<https://github.com/keycloak/keycloak>).
2. **The user's chosen purpose can raise protection but never lower the app's floor.** Picking "Personal" does not let someone use the Work app with weaker security. The app's preset is the minimum.

### What this changes in the plan

- **We must be an OIDC provider for first-party apps** (authorization code + PKCE, refresh rotation, pairwise subjects, consent screen). I previously listed this as out of scope. It is now P1. References: Ory Hydra (<https://github.com/ory/hydra>) and the Go OAuth2 SDK Ory Fosite (<https://github.com/ory/fosite>), both Apache-2.0, plus Keycloak for behavior. Verify licenses and maturity before choosing to build on Fosite or write a minimal provider.
- **Native and offline clients** (the legal app) use PKCE and, where needed, the device-code flow, then hold a signed offline grant (section 8).
- **Cross-app single sign-on session** lives on one auth domain with a secure cookie. Each app gets its own tokens.
- **Account hub UI:** one page showing connected apps, personas, devices, and billing across all apps. Billing becomes **one customer, many subscriptions**, which is a real selling point.
- **Risk to be honest about:** an account that unlocks everything is a single target. Passkeys, device recognition, step-up, and clear "revoke app" controls are therefore P1, not optional.

## App presets (the security floor each app declares)

Your apps differ mainly in how much is at stake if an account is compromised and how much friction users will tolerate. Instead of three products, we ship **one core with three presets**. Each app picks one as its floor, and the user's purpose selects the persona inside it. A preset is a named bundle of security policy, session rules, data handling, and UI defaults. It is the same idea as a Keycloak *realm* (<https://github.com/keycloak/keycloak>) or an Authentik *flow* set (<https://github.com/goauthentik/authentik>), but chosen with one line of config.

```go
am, _ := goldaccountmanager.New(goldaccountmanager.Config{
    Preset: preset.Work, // or preset.Leisure, preset.Utility
})
```

| | **Utility** | **Leisure** | **Work** |
|---|---|---|---|
| Example | Simple tools with user preferences | Dating app: full profiles, images, private info | Legal software, and anything billed per seat |
| Stakes | Low | High for privacy and safety, medium for access | Highest for confidentiality and compliance |
| Sign-up | Anonymous device account, upgrade later | Phone or email magic link, passkey offered | Invite-only or SSO, MFA required |
| Primary login | Device token, magic link | Magic link, SMS code, passkey | Passkey or password + TOTP, SSO |
| Session length | Long, sliding | Medium, sliding | Short absolute, re-auth for sensitive actions |
| New device | Silent | Notify user | Notify, may require approval |
| Data handling | Preferences only | Field-level encryption for private data, media storage, consent | Encryption at rest, retention rules, no telemetry |
| Audit | Minimal | Security events | Full, tamper-evident |
| Billing | Optional, per user | Subscription, boosts | Per seat, plans, invoices |
| Offline | Local-first | Online | **Offline-capable** (see below) |
| Admin UI | Basic | Moderation tools | Full admin, roles, impersonation guardrails |

Presets are starting points. Every setting stays individually overridable, which borrows the SuperTokens recipe-and-override pattern (<https://github.com/supertokens/supertokens-core>).

## Feature catalog

Priority: **P0** is the MVP, **P1** is needed by the first real app, **P2** comes later. Preset columns show where the feature is default-on: **U**tility, **L**eisure, **W**ork.

### 1. Authentication

| Feature | Pri | Presets | Reference | Notes |
|---|---|---|---|---|
| Email + password (argon2id) | P0 | W | Kratos password method | Optional for U and L |
| **Email magic link** | P0 | U L | Kratos "code/link" methods, SuperTokens passwordless | Single-use, short expiry, bound to the requesting browser to defeat link forwarding |
| **SMS / text one-time code** | P1 | L | SuperTokens passwordless, Keycloak SMS extensions | Behind a `SMSSender` interface (Twilio, etc.). Needs per-number and per-IP rate limits and cost caps to resist SMS pumping fraud. SMS is weaker than other factors (SIM-swap risk), so offer it as convenience or fallback, not the only factor for Work |
| Passkeys (WebAuthn) | P1 | all | <https://github.com/go-webauthn/webauthn> | Best UX and security. Make it the headline for Work |
| TOTP + recovery codes | P1 | W | <https://github.com/pquerna/otp>, Keycloak OTP | |
| Social / OIDC login | P2 | L U | Casdoor provider catalog (<https://github.com/casdoor/casdoor>) | One small `Provider` interface |
| Enterprise SSO (OIDC, then SAML) | P2 | W | Keycloak (<https://github.com/keycloak/keycloak>), Zitadel | OIDC first. SAML only if a customer needs it |
| Anonymous / device account | P1 | U | Kratos has no direct equivalent. Design our own | Create a local identity, later "upgrade" by attaching a credential without losing data |

### 2. Flows (the part that keeps clients simple)

Every journey is an explicit flow with an ID, a state, and a list of steps, as in Kratos self-service flows (<https://github.com/ory/kratos>) and Authentik stages (<https://github.com/goauthentik/authentik>). Clients render whatever step the server returns, so adding MFA later does not break existing UIs.

- Flows: registration, login, recovery, verification, settings, step-up, device approval.
- Steps are composable and ordered per preset: `identify → challenge → mfa → device-check → session`.
- Keycloak's **required actions** (verify email, update password, accept terms) map to steps we can inject after login (<https://github.com/keycloak/keycloak>).
- **P0** flows: registration, login, recovery, verification. **P1:** step-up, device approval.

### 3. Sessions and device recognition

| Feature | Pri | Reference | Notes |
|---|---|---|---|
| Opaque session tokens, stored hashed | P0 | Kratos sessions | |
| **Refresh rotation with theft detection** | P0 | SuperTokens | Reuse of an old refresh token revokes the whole family |
| Sliding + absolute expiry | P0 | Kratos, Keycloak | Per preset |
| **Device recognition** | P1 | Keycloak, Authentik | Long-lived signed device cookie plus coarse fingerprint (user agent, platform) and IP/geo hints. Used to decide "trusted vs new device", never as a sole credential |
| New-device alerts (email/SMS) | P1 | | "Was this you?" with one-tap revoke |
| Device list, revoke one, sign out everywhere | P1 | Keycloak account console | |
| Step-up auth for sensitive actions | P1 | Kratos `aal2` / privileged sessions | e.g. change email, export data, refund |

Be honest in the docs about fingerprinting: it's a risk signal that reduces friction, not proof of identity.

### 4. Profiles and user data

| Feature | Pri | Presets | Reference | Notes |
|---|---|---|---|---|
| Extensible profile fields | P0 | all | Kratos identity traits (JSON Schema) | Schema per app, validated server-side |
| Public vs private field visibility | P1 | L | | Per-field visibility so the app can't leak private data by accident |
| **Field-level encryption** for private data | P1 | L W | | Envelope encryption with a `KeyProvider` interface (local key, KMS). Keys rotatable |
| Media (profile images) | P1 | L | | Store behind a `BlobStore` interface (disk, S3). Auth server stores references and permissions, not bytes by default. Content scanning and moderation hooks are the app's job, but we provide the hook points |
| Consent records and terms acceptance | P1 | L W | Keycloak required actions | Versioned, timestamped |
| Data export and account deletion | P1 | L W | | Needed for GDPR/CCPA style rights. Deletion = soft-delete window, then hard purge, plus audit entry that keeps no personal data |
| Block / report primitives | P2 | L | | Minimal hooks only. Dating-app moderation logic belongs in the app |

Dating-app note: private info and images are the highest-harm data we'd hold. That is why encryption, visibility rules, and short-lived signed media URLs are P1 for the Leisure preset and not afterthoughts.

### 5. Authorization

| Feature | Pri | Reference | Notes |
|---|---|---|---|
| Roles and permissions, `Can(user, perm)` | P0 | Keycloak roles | Stored as data |
| Groups / organizations / teams | P1 | Keycloak groups, Zitadel orgs | Needed for Work apps, and for per-seat billing |
| Pluggable policy engine | P2 | Casbin (<https://github.com/casbin/casbin>) | Offer a Casbin adapter, but keep the built-in RBAC dependency-free |
| Relationship-based permissions ("can edit this matter") | P2 | Ory Keto (<https://github.com/ory/keto>) | Legal software will likely want per-matter access. Design the permission interface so this can be added |

### 6. Audit and the event-sourcing decision

**Recommendation: do not fully event-source the core.** Use an **append-only, hash-chained audit log** instead.

- Zitadel derives all state from events (<https://github.com/zitadel/zitadel>). That gives a perfect history but makes every query, migration, and deletion harder, which matters when privacy deletion is a requirement (dating apps).
- A separate append-only audit table gives most of the benefit: who did what, when, from where. Each row stores the hash of the previous row, so tampering is detectable. That matters for legal work.
- Personal data is kept out of audit rows (use user IDs, not names or emails) so deletion requests don't conflict with the log.
- Revisit if we later need point-in-time reconstruction of account state.

Scope: login success/failure, factor changes, role changes, impersonation, exports, deletions, billing changes. **P0** for the table and writer, **P1** for hash chaining and an export command.

### 7. Billing and entitlements

Billing is **later**, but the schema must leave room now.

- **P1 (design only):** every user belongs to a `subject` (a user or an organization) that can own a `plan` and `entitlements`. Authorization checks can read entitlements as well as roles.
- **P2:** `BillingProvider` interface with a Stripe adapter. Per-seat counting for organizations, webhook handling, and a usage-metering hook.
- We deliberately do not build invoicing, tax, or dunning ourselves. Delegate to the provider.
- Reference: Keycloak and Kratos don't do billing, so this is a differentiator and also a place to stay small.

### 8. Offline mode (legal software)

The legal app works offline but accounts live online. This is the hardest and most distinctive requirement, and no listed project solves it, so it needs its own design before code.

Proposed approach:
- **Signed offline grant.** After an online login, the server issues a time-limited, device-bound grant (signed token listing the user, roles, entitlements, and an expiry). The app verifies it locally with the server's public key. Expired grant means re-authenticate online.
- **Local unlock.** On the device, a passphrase, passkey, or OS biometric unlocks a local encrypted store. This is separate from the server login.
- **Revocation lag is explicit.** Offline devices can't learn about revocation. The grant lifetime *is* the revocation window, and it should be configurable per customer (for example 24 hours to 14 days).
- **Sync.** Queued, signed account changes sync on reconnect. Conflict rules are simple: server wins for credentials and roles, last-writer-wins for preferences.
- **No hidden telemetry.** Confidentiality is the selling point, so the offline client makes no network calls except explicit sync.

Open question: is the offline piece a Go library embedded in a desktop app, or a separate client SDK? See questions below.

### 9. Admin and "easy demo, clean UI every time"

This is a first-class requirement, not polish.

- **One embedded admin and account UI**, server-rendered, themeable with CSS variables (inspired by Casdoor's UI-first approach and the Keycloak account console: <https://github.com/casdoor/casdoor>, <https://github.com/keycloak/keycloak>).
- **Two surfaces:** an **account page** for end users (profile, security, devices, billing) and an **admin console** (users, roles, orgs, sessions, audit).
- **Demo mode:** `goldd demo` starts with seeded users in all three presets, a log-only mailer and SMS sender (codes appear in the terminal and in a dev inbox page), and no external services needed. Target: from clone to a working login in under two minutes.
- **Preset switcher in demo mode** so you can show the same app as Work, Leisure, and Utility.
- UI rules: one primary action per screen, plain language, no jargon, the same layout in every preset, accessible by default (keyboard, contrast, screen readers).
- Impersonation with banner, time limit, and audit entries (P1, Work only).

### 10. Operations

- **P0:** single binary, SQLite, migrations, structured logs.
- **P1:** Postgres, health checks, Docker image, rate limiting (in-memory first, `RateLimiter` interface for Redis).
- **P1:** `export` / `import` commands, including legacy password-hash import.
- **P2:** metrics endpoint, multi-region guidance.

## What we are deliberately not building (yet)

- Full SAML IdP and the Keycloak-style federation matrix (LDAP, Kerberos). Keycloak already does this well. We could interoperate with it instead.
- Being an OAuth2/OIDC provider for **third-party** developers (open client registration, marketplace). We are an OIDC provider for your own first-party apps only. Revisit when outside teams need it.
- Fraud and moderation systems. We expose hooks and signals only.
- Multi-tenancy at Zitadel's depth. Organizations and groups yes, full tenant isolation later.

## Suggested build order

1. **MVP (P0):** magic-link + password login, flows, sessions with rotation, roles, audit table, SQLite, demo mode, minimal UI. Plus the thinnest slice of the core offer: **one account, two demo apps, one-tap "Continue as…"** (first-party OIDC code + PKCE, a consent screen, and the purpose picker). If the two-app demo isn't compelling, nothing else matters yet.
2. **Leisure readiness (P1):** SMS codes, passkeys, device recognition and alerts, profile visibility, field encryption, media references, consent, export/delete.
3. **Work readiness (P1):** TOTP, step-up, organizations, hash-chained audit, impersonation, entitlement schema.
4. **Offline and billing (P2):** signed offline grants and local unlock, Stripe adapter, per-seat billing.
5. **Integrations (P2):** social login catalog, OIDC/SAML SSO, Casbin and Keto adapters.

## Open questions

0. **Core offer:** (a) Should personas be unlinkable by default, as proposed (pairwise IDs, separate profiles), or do you want one shared profile across apps by default? (b) Is the purpose picked per account, per app, or both? I recommend per app, with a remembered default. (c) Will all apps live under one parent domain (simplest SSO) or on unrelated domains (needs full OIDC redirects everywhere)?

1. **Offline architecture:** embedded Go library in a desktop app, or a client SDK in another language? What platforms does the legal app target?
2. **Legal data:** is a hosted option planned, or must the account service itself be self-hosted by each firm? This changes the offline grant design.
3. **SMS provider and budget:** is Twilio acceptable, or a local-first option? Which countries?
4. **Dating app media:** will photos be stored by the auth service, or by the app with us holding access rules only? (We recommend the latter.)
5. **Compliance targets:** GDPR/CCPA only, or also anything sector-specific for legal work? We can support the technical controls but not certify compliance.
6. **Client languages:** are your apps all Go, or do we need JS/mobile SDKs soon?
7. **Event-sourcing:** are you comfortable with the recommendation in section 6 (append-only audit, not full event sourcing)?
