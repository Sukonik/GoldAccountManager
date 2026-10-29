# Scope: what we build first

This page is the decision. [FEATURES.md](FEATURES.md) is the long wishlist, and [PLAN.md](PLAN.md) is the phase plan. If they disagree with this page, this page wins.

## Requirements (from the owner)

1. **User accounts for any of my apps.** Many apps, one toolkit.
2. **Each app is isolated.** A new account every time. No shared users. A dating app user and a legal app user must never feel linked, and the system must not link them.
3. **Phone first, email second, Google third.** Users must get in easily and *stay* in.
4. **Never kick good users out.** The owner's experience with accounts on a dating app being repeatedly logged out or banned by Facebook login is the problem to avoid.
5. **Scale at low cost, and free to host.** Free versions with limited user counts at first.
6. Simple to demo, with a clean UI. Prefer existing free systems to running our own.

## Decision 1: every app is its own island

This **replaces the earlier "one account across all apps" idea.**

- An app is a **separate user pool** (a tenant): its own users, sessions, roles, settings and quotas.
- The same person using two apps has two unrelated accounts. There are no cross-app IDs, no shared sessions, and no "Continue as…" screen.
- Because nothing is shared, **we no longer need to be an OIDC provider, and the apps can be on unrelated domains** with no cross-domain single sign-on.
- Phone numbers and emails are stored per app. Lookup uses a keyed hash with an app-specific secret, and the readable value is encrypted separately for sending messages. So even our own database has no easy "same phone in two apps" join. (A determined operator with all the keys could still link them, so the privacy promise depends on trusting the operator. Say that honestly to users.)
- **Autofill is optional and user-driven**, a later feature. When a user signs up to a new app, they can choose "fill in my details" from their own device (browser or OS autofill, or a saved card in the account hub). The screen states exactly what is sent: *"This app will get your name and email. Nothing else. It is not linked to your other apps."* There is no server-side link between accounts.
- The **purpose** (Work / Personal / Utility) becomes a property of **the app**, as its preset, which sets its security and session defaults. It is no longer a user choice.

## Decision 2: phone first, and never kick good users out

### Sign-in methods in v0.1

1. **Phone number + SMS code** (default for the Leisure preset)
2. **Email magic link**
3. **Google login**
4. Guest first, then link a real login later (keeps data, no friction)

### Why users get kicked out, and what we do instead

| Common cause | Our rule |
|---|---|
| Short sessions, so people re-verify constantly | Long sliding sessions: 90 days or more for Leisure and Utility. Stricter windows only for Work |
| Refresh-token theft detection that revokes on any reuse, which trips on flaky networks and double taps | Rotation with a **short grace window**. Reuse inside it is treated as a retry. Reuse outside it asks the user to verify, it does not silently log them out |
| Risk signals (new IP, new device) that trigger a lockout or ban | Signals only ever add a **challenge** (a code), never an automatic ban or an unrecoverable lock |
| Losing the phone number or email means losing the account | Let users add a second method (email + phone) early, and offer recovery through whichever remains |
| SMS needed on every login | SMS only for sign-up, a new unrecognized device, and recovery. After that, the device stays signed in, and a passkey can replace SMS later |
| Third-party login (Facebook) can revoke your account at any time | Our account is ours. Google login is a convenience that can be detached, and a phone or email always remains |

### SMS cost control

SMS is the one cost that scales with users, and it attracts fraud. There is no truly free SMS at volume.
- Send codes only when needed (see above).
- Cap sends per number, per IP, per app per day, and per app per month. The cap is part of each app's quota.
- Block premium and high-fraud country prefixes by default. The owner picks allowed countries.
- Use an `SMSSender` interface so the provider can change. Candidates to compare: Twilio Verify, Firebase phone auth, Vonage, regional providers. **Check current prices and free allowances yourself. I have not verified them.**
- In demo mode, codes print to the terminal at no cost.

## Decision 3: free hosting

Free tiers change often, so treat this as a starting list and verify each.

| Option | Good for | Watch out for |
|---|---|---|
| **Oracle Cloud "Always Free" VM** | Our single Go binary + SQLite, persistent disk | Sign-up can be rejected, idle instances can be reclaimed, and you do your own backups |
| **Google Cloud Run** (free allowance) | Go in a container, scales to zero | Stateless, so you need an external Postgres. Cold starts |
| **Free managed Postgres** (e.g. Neon, Supabase) | Pairs with Cloud Run or similar | Free projects can pause when idle, and have size limits |
| **Free email providers** (e.g. Resend, Brevo) | Magic links | Daily send limits on the free plan |
| **Fly.io, Render, Railway** | Easy deploys | Free allowances have been reduced or removed before. Check now |
| **Home server** | Truly free, and you own it | Uptime, dynamic IP, and exposing it safely |

Design consequence: SQLite for the simplest free VM, **and a Postgres store early** so Cloud Run-style hosting is possible. Back up SQLite continuously (Litestream to free object storage is a common pattern, verify).

## Decision 4: build the engine, or adapt one?

Since you prefer existing systems, this is the biggest open choice. Phone-first, isolated per-app pools and free hosting are exactly what some existing open-source auth servers already do.

| Option | What you get | Cost to you |
|---|---|---|
| **A. Write our own auth engine in Go** (the plan so far) | Full control, tiny footprint | Longest build. You own every security bug |
| **B. Gold as a thin layer over an existing engine.** Candidates: [Supabase Auth](https://github.com/supabase/auth) (Go, phone OTP, magic link, Google), [Ory Kratos](https://github.com/ory/kratos) (Go), [SuperTokens](https://github.com/supertokens/supertokens-core) (Java core) | Proven login, phone, email and sessions. Gold adds per-app quotas, presets, the admin and demo UI, and the "never kick out" rules | Smaller build. Limited by the engine's behavior. Verify licenses and how each handles phone login and per-app isolation |
| **C. Firebase or Supabase hosted, today** | Fastest to ship, free tiers, phone auth built in | Not self-hosted. Vendor limits. Per-app isolation means one project per app |

**Recommendation: start with B or C for the first real app and make the `AuthEngine` an interface.** Prove your apps first. Keep Gold's own value (quotas, presets, clean admin, the isolation promise) as the layer you build. Write our own engine only if an existing one blocks you. This is a recommendation, not a decision. I have not tested any of these engines.

### Decision 4 outcome (owner): combine B and C

Use a hosted engine now (C) and build Gold as the layer on top (B), behind an `AuthEngine` interface.

Findings from a quick web check (third-party sources, **re-verify on the vendors' own pricing pages**):

| Platform | Free-tier facts found | Fit |
|---|---|---|
| [Supabase](https://makerkit.dev/blog/md/saas/supabase-pricing) | 50,000 MAU, 500 MB database, free projects pause after 1 week idle. Phone-auth SMS cost and free project count not confirmed | Leading candidate for the auth engine |
| [Neon](https://neon.com/faqs/free-plan-limits-and-quotas) | Serverless Postgres, 100 free projects, 0.5 GB each. [Neon Auth](https://neon.com/docs/changelog/2025-12-12) is new (reported 60K MAU, unconfirmed) | Good for Gold's own tables and one project per app. Auth is less proven |
| [Firebase](https://blog.logto.io/it/firebase-authentication-pricing) | Email, social and anonymous are free. Phone sign-in needs the paid Blaze plan (first 10 SMS a day free, then about $0.01 to $0.46 each) | Familiar, but not free for phone-first |

Because SMS is the real cost on every platform, the per-app SMS cap and country allow-list are core features.

**To verify before building:** Supabase's current free-project count, which SMS provider its phone auth needs and who pays, and how idle-pausing affects a live app.

## Quotas: the free-tier feature

Every app has a plan with limits Gold enforces:

| Setting | Meaning | Example |
|---|---|---|
| `max_users` | Hard cap on accounts for this app | 100 on Free |
| `max_monthly_active` | Optional soft cap | 50 |
| `sms_monthly_cap` | Max SMS codes per month | 200 on Free |
| `on_limit` | `block_signups`, `waitlist`, or `notify_only` | `waitlist` |

- Existing users are never locked out when a cap is hit. Only new sign-ups are affected.
- A full app shows a plain "This app is full, join the waitlist" screen.
- Quotas belong to the **app**. End-user billing comes later.

## Version 0.1: the only things we build

1. **Apps as isolated pools:** create an app with its own ID, redirect URLs, preset, plan and quotas.
2. **Sign-in:** phone + SMS code, email magic link, Google login, guest-then-link.
3. **Sessions:** long sliding sessions, rotation with a grace window, device list, revoke.
4. **Roles:** a simple role field per app.
5. **Quotas** including the SMS cap.
6. **Admin page** with clean UI: apps, users, quotas, sessions.
7. **Audit table:** append-only record of sign-ins and admin actions, holding user IDs and no personal data.
8. **Demo mode:** two seeded apps (one Work, one Leisure), codes and links printed or shown in a dev inbox.

## Not in v0.1 (parked in FEATURES.md)

Cross-app accounts and OIDC provider, passkeys, TOTP, field encryption, media, billing and Stripe, offline legal mode, SAML and enterprise SSO, organizations, Casbin and Keto adapters, hash-chained audit, and device-fingerprint recognition beyond a simple trusted-device cookie.

## Done means

A stranger can run `goldd demo`, sign in to the Leisure demo app with a phone code (printed to the terminal) and to the Work demo app with a magic link, confirm that the two accounts are completely separate, hit a 100-user cap in a test app and see the waitlist, stay signed in after a simulated network retry, and see everything in the admin page, in under five minutes.

## Still open

1. **Build the engine or adapt one?** (Decision 4.) This sets what Phase 0 even is.
2. **SMS:** which countries do you need, and what monthly budget is acceptable?
3. **Autofill:** is a user-held details card enough, or do you want something deeper? Keep it out of v0.1 either way.
