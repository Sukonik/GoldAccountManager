# Research: engines, and a lightweight, unique take

Findings from web searches and from reading [Sukonik/payout-lab](https://github.com/Sukonik/payout-lab) on 2026-10-29. Vendor numbers come mostly from third-party sources and **must be re-verified on the vendors' own pages** before any decision rests on them.

## 1. Existing engines compared

| Option | Kind | Free tier (as found) | Phone / SMS | Fit for us |
|---|---|---|---|---|
| **[Better Auth](https://better-auth.com/docs/plugins)** | Open-source **TypeScript library**. Runs inside your own app, with your own database | Free (you host) | Phone-number plugin (phone + OTP). You supply the SMS provider and pay per message | Lightest option. Plugins for [magic link](https://better-auth.com/docs/plugins/magic-link) (you supply the email sender), anonymous (guest) sessions, and organizations. No vendor pool limits, no pausing. Docs show v1.6 stable and v1.8 beta, so pin a version |
| **[Clerk](https://clerk.com/articles/clerk-pricing-explained)** | Hosted | Reported 50,000 monthly retained users on free since Feb 2026 (older pages say 10,000) | SMS price and free-plan availability not confirmed | Polished UI, but hosted and priced per user at scale. Weak fit for "own the data" |
| **[Auth0](https://auth0.com/pricing?pm=true)** | Hosted | 25,000 MAU on free | Sources conflict on whether SMS is on free. Reported paid entry around $35/month for 500 MAU | Strong on features, expensive growth path. Weak fit |
| **[Appwrite](https://appwrite.io/alternative-to/auth0)** | Open-source backend, cloud or self-host | Reported 75,000 free MAU on cloud | Forum reports say the free cloud plan allows almost no phone OTP. Self-hosting is the stated way around that, but SMS setup on self-host is unconfirmed | Self-hostable, heavier than a library (a whole backend) |
| **[Supabase Auth](https://makerkit.dev/blog/md/saas/supabase-pricing)** | Hosted or self-host | 50,000 MAU, pauses after a week idle | SMS provider and cost unconfirmed | Earlier front-runner. Pausing and project limits hurt live apps |
| **[Neon Auth](https://neon.com/docs/changelog/2025-12-12)** | Hosted, newer | Reported 60,000 MAU, 100 free projects | Not confirmed | Unproven |

**Pattern across all of them:** nobody's free tier makes phone-first free. SMS is always a pass-through cost. The only way to make it cheap is to **send fewer SMS**.

**Language note.** Better Auth, Clerk, Auth0 and Appwrite SDKs are JavaScript/TypeScript-first. The repo was described as "written in Go", but `payout-lab` is plain JavaScript with Node tests and static hosting. If your apps are JS, Go is now an unforced extra language. See the open questions.

## 2. What payout-lab already proves

`payout-lab` ([README](https://github.com/Sukonik/payout-lab/blob/main/README.md), [packet format](https://github.com/Sukonik/payout-lab/blob/main/docs/packet-format.md), [links](https://github.com/Sukonik/payout-lab/blob/main/docs/links.md)) is a no-signup, no-server, $0 app where **the user's data is a file they own**, called a *packet*:

- **Packet = account.** A `.payout` JSON file holds the portfolio, settings and saved reports. Open it on any device to continue. There is no database.
- **Identity without a server.** A random `portfolioId`, plus `revisionId`, `parentRevisionId` and a `lineage` list, so two copies can be classified as identical, newer, older or **diverged**. "No silent last-write-wins": a diverged copy opens as a separate copy.
- **Integrity.** A SHA-256 checksum catches accidental damage. The docs state plainly that it is not a signature.
- **Safe parsing.** Size limit, whitelisted fields only, bounded numbers, no executing file content, a decompression-bomb guard.
- **Provenance per field.** Each value records `src`, `asOf` and `manual`, and manual values are protected from automatic updates.
- **Several ways to carry it:** a file, a remembered-on-this-device copy, a bookmark (id only, safe to share), a snapshot link (data inside the URL fragment, never sent to a server) and a printable QR card.
- **Honest limits stated in the docs:** unencrypted, the device copy is not a backup, and links expose data.
- **$0 hosting, a design system and MPL-2.0:** static GitHub Pages and Actions, the vendored Green Ion design system (dependency-free, light and dark, WCAG AA contrast per the README), and the same license as this repo. Its roadmap already lists "encrypted packets, passkeys or password-manager unlock keys."

These are most of what this project has been trying to design: isolated per-app accounts, never locked out, free, offline-capable, easy to demo with a clean UI.

## 3. The unique take: packet-first accounts

> **Your account is a file you own. A server is optional, and gets only as much as the app truly needs.**

Most auth products start from a server database and add export later. We start from the user-held packet and add servers only where a feature requires one. Three tiers, chosen per app:

| Tier | What exists | Server cost | Good for |
|---|---|---|---|
| **0. Packet only** | A packet (file + on-device copy), optionally encrypted and unlocked with a passkey or password manager. No sign-up, no phone, no email | **$0** (static hosting) | Utility apps, preferences, tools like payout-lab |
| **1. Verified packet** | Tier 0 plus a tiny verification service. The user proves control of a phone or email once. The service signs a short **attestation** ("this packet key belongs to a verified phone") and stores only a keyed hash for recovery | Tiny and stateless-ish. SMS only at verification and recovery | Apps that need a real identity or recovery but little server data |
| **2. Hosted account** | A normal server-side user record (Better Auth or another engine) with the packet as an export, backup and portability layer | Real, but quota-capped per app | Apps whose server must hold the data: dating (matches, messages), billing |

Why it fits each stated goal:

| Goal | How the packet-first design helps |
|---|---|
| **Isolated per app** | Each app has its own packet format and key. There is nothing shared to link |
| **Never kick good users out** | The user holds their account. A server outage, ban or expired session cannot delete it. Recovery is the file or the second verified method |
| **Free and low cost** | Tier 0 costs nothing and has no user count to limit. Quotas only matter in Tiers 1 and 2 |
| **Fewer SMS** | Tier 0 sends none. Tier 1 sends one per verification or recovery |
| **Offline legal app** | The packet plus a server-signed attestation **is** the offline grant already planned. A lawyer's data never has to leave the device |
| **Easy demo, clean UI** | Open the page and it works. Reuse Green Ion for a consistent look |
| **Own your data** | Literal: it is a file. The same word and ideas as payout-lab |

### What a packet-first account does not do (be honest)

- **A file alone can't enforce user counts, roles or entitlements.** Anyone can edit a JSON file. Anything the server must trust (a paid plan, an admin role) has to be a **server-signed grant** checked against the server's public key. Pure Tier 0 apps get no quotas, by design.
- **Lost file, lost account** unless the user also verified a phone or email (Tier 1) or keeps a backup. Say so up front, as payout-lab does.
- **Dating-style apps need Tier 2.** Matching and messaging need server-side data. The packet is then a portability and export feature, not the system of record.
- **Unencrypted packets are risky for private data.** Encryption (passkey or password-manager key) must come before any sensitive app uses packets.
- **Cross-device sync is manual** in Tier 0. Fine for utilities, painful for a daily-use app. Tier 1 or 2 can add sync later.

## 4. A lightweight build, concretely

1. **Packet core library** (JavaScript, no dependencies, reusing payout-lab's packet ideas): create, validate (whitelisted fields), lineage and relation check, checksum, import and export, optional encryption wrapper. Tests in the same Node style.
2. **Verification service** for Tier 1: a very small stateless service, deployable to a free serverless host, with SMS and email behind interfaces and per-app caps.
3. **Hosted adapter** for Tier 2: start with Better Auth, since it is a library on your own database with phone, magic-link, anonymous and organization plugins. Keep an `AuthEngine` interface so it can be swapped.
4. **Demo:** a static page with two sample apps. One is Tier 0, one is Tier 2. Both are visibly isolated.

## 5. Open questions

1. **Language:** are your apps JavaScript or TypeScript (as payout-lab is)? If so, I'd recommend dropping Go and building this in JS/TS to match, and the repo description should change.
2. **Which of your apps are Tier 0, 1 and 2?** Utility apps look like Tier 0, legal like Tier 0 or 1 plus offline grants, dating like Tier 2.
3. **Reuse from payout-lab:** is it OK to lift its packet core into this project as a shared library? Both are MPL-2.0.
4. **Encryption first?** I'd make passkey-unlocked encryption a requirement before any private data goes into a packet.
