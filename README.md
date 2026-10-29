# ⚡ GoldAccountManager

**Your account is a file you own.** 📁

An open-source **Go** toolkit for user accounts that start with **no server, no sign-up and no cost**, and add confirmation by email, phone or Google only when an app really needs it. Every app is its own isolated account space, so a dating app and a legal tool never share users, IDs or sessions, and nothing links them.

[![CI](https://github.com/Sukonik/GoldAccountManager/actions/workflows/ci.yml/badge.svg)](https://github.com/Sukonik/GoldAccountManager/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/Go-1.24%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MPL--2.0-blue)
![Status](https://img.shields.io/badge/status-Phase%200%20%C2%B7%20early%20development-orange)

> 🚧 **Honest status:** this is **Phase 0**. The packet format, signed attestations, a small command line and the documentation site are built and tested. There is **no server, no web sign-in and no hosted tier yet**, and nothing here has had an external security review. See the [roadmap](#-roadmap).

## 📑 Contents

[🌐 Website and versions](#-website-and-versions) · [📦 What is a packet?](#-what-is-a-packet) · [🕰️ History: from Payout Lab](#️-history-from-payout-lab) · [🧱 Three tiers](#-three-tiers) · [✅ Free-first verification](#-free-first-verification) · [🧰 Use it from Go](#-use-it-from-go) · [💻 Command line](#-command-line) · [🎨 Blue Bolt UI](#-blue-bolt-ui) · [🧪 Quality checks](#-quality-checks) · [🗺️ Roadmap](#-roadmap) · [📚 All resources](#-all-resources) · [🗃️ Project layout](#️-project-layout) · [🛠️ Development](#️-development) · [🤝 Contributing](#-contributing)

---

## 🌐 Website and versions

📖 **Documentation site:** <https://sukonik.github.io/GoldAccountManager/>

The main address always shows the **latest** version. Every release is also **preserved at its own path**, so old links keep working after the site moves on. A preserved build is the exact set of web files at release and does not update. This is the same approach Payout Lab uses.

| Version | Released | What it covers | 🔗 Latest | 📌 Preserved |
|---|---|---|---|---|
| **0.1.0** · Phase 0: Packets ⭐ *current* | 2026-10-29 | Packet format, signed attestations, the `goldd` command line, Blue Bolt UI v0.1, and seven documentation pages | [Open](https://sukonik.github.io/GoldAccountManager/) | [`/v0.1/`](https://sukonik.github.io/GoldAccountManager/v0.1/) |

The site's own [Versions page](https://sukonik.github.io/GoldAccountManager/versions.html) lists every version and is generated from [`site/versions.json`](site/versions.json).

**Pages in this version:**

| | Page | Source |
|---|---|---|
| 🏠 | [Home](https://sukonik.github.io/GoldAccountManager/) | [`site/pages/index.html`](site/pages/index.html) |
| 📦 | [Packets](https://sukonik.github.io/GoldAccountManager/packets.html) | [`site/pages/packets.html`](site/pages/packets.html) |
| ✅ | [Verification](https://sukonik.github.io/GoldAccountManager/verification.html) | [`site/pages/verification.html`](site/pages/verification.html) |
| 🕰️ | [History](https://sukonik.github.io/GoldAccountManager/history.html) | [`site/pages/history.html`](site/pages/history.html) |
| 🎨 | [Blue Bolt UI](https://sukonik.github.io/GoldAccountManager/blue-bolt.html) | [`site/pages/blue-bolt.html`](site/pages/blue-bolt.html) |
| 🗺️ | [Roadmap](https://sukonik.github.io/GoldAccountManager/roadmap.html) | [`site/pages/roadmap.html`](site/pages/roadmap.html) |
| 🏷️ | [Versions](https://sukonik.github.io/GoldAccountManager/versions.html) | [`site/pages/versions.html`](site/pages/versions.html) |

> ⚙️ **GitHub Pages setup:** the built site lives in [`docs/`](docs). In the repository's **Settings → Pages**, deploy from the branch that holds `docs/`, folder **`/docs`**. The site is plain static files (`docs/.nojekyll` is included), so there is no build step on GitHub.

---

## 📦 What is a packet?

A **packet** is one plain JSON file that is a user's account for **one app**: the app's data, an identity, a revision history, and any server-signed attestations. Open it on any device to continue. No sign-up, no database, no server.

```json
{
 "format": "gold-packet",
 "schemaVersion": 1,
 "appId": "notes-demo",
 "packetId": "pk_5rh8n3m0ppqxr",
 "name": "Sam's notes",
 "revisionId": "rv_ba9m8znr3v9a5",
 "parentRevisionId": "rv_qvqmeam54cad7",
 "lineage": ["rv_qvqmeam54cad7", "rv_ba9m8znr3v9a5"],
 "payload": { "theme": "dark", "fontSize": 16 },
 "attestations": [ { "kind": "email", "method": "email-reply", "...": "..." } ],
 "checksum": { "alg": "sha-256", "value": "840edb95…" }
}
```

*(Shortened. A complete, real file is [`site/examples/attested.gold`](site/examples/attested.gold), and a test keeps it valid.)*

### ✨ Why a file?

- 🔓 **Never locked out.** A ban, an outage or an expired session can't take away a file the user holds.
- 💸 **Free to start.** Tier 0 has no users to count and nothing to host.
- 📉 **Fewer paid messages.** SMS costs money everywhere, so the cheapest code is the one never sent.
- 🕵️ **Private by design.** Attestations carry a keyed hash, never the email or phone number, and differ for every app.
- ✈️ **Offline friendly.** A signed packet can be the offline grant for desktop software.
- 🏝️ **Isolated per app.** A packet only opens in the app it was made for.

### 🔎 How a packet is protected

| | |
|---|---|
| 🧱 **Strict parsing** | 5 MiB file cap, known fields only, bounded values, payload depth and size limits, nothing is ever executed |
| 🔤 **Case-sensitive names** | `AppId` is rejected, not quietly accepted. Found by fuzzing: Go's JSON decoder matches names case-insensitively but other readers don't |
| 🌿 **Revision lineage** | Two copies are *identical*, *newer*, *older* or *diverged*. There is **no silent last-write-wins** |
| 🧾 **Checksum** | SHA-256 of canonical JSON. Catches accidents only |
| ✍️ **Signed attestations** | What a server must trust (a confirmed phone or email) is Ed25519-signed and bound to one app and one packet |

> ⚠️ **A checksum is not a signature.** Anyone can edit a packet and recompute it. Never trust an unsigned packet for roles, plans or identity.

**Known limits:** packets are **not encrypted yet** (passkey-based encryption is planned and must land before any private data uses packets); a lost file is a lost account unless the user also confirmed an email or phone; and sync between devices is manual in Tier 0.

📘 Full specification: [`docs/packet-format.md`](docs/packet-format.md)

---

## 🕰️ History: from Payout Lab

The packet is not a new idea. It was proven first in **[Payout Lab](https://github.com/Sukonik/payout-lab)** 🧪, a free, no-sign-up dividend portfolio tracker. It has no accounts and no server, runs on GitHub Pages for $0, and the user's portfolio is a **`.payout` packet** they own.

### 🧭 Timeline

| Release | Date | What it added |
|---|---|---|
| 🏁 **Payout Lab V1** | baseline | The first no-signup tracker, preserved as a build |
| 📦 **[V2 · Portable Workspace](https://github.com/Sukonik/payout-lab/pull/21)** | 2026-10-13 | **Packets are introduced**: the `.payout` file, revision lineage, checksums, per-value data provenance, CSV import and "Continue" |
| 🧾 **[V3 · Access & Receipts](https://github.com/Sukonik/payout-lab/pull/28)** | 2026-10-13 | Saved reports, bookmarks, snapshot links (data inside the URL fragment) and [QR cards](https://github.com/Sukonik/payout-lab/pull/29) |
| ✂️ **V4 · Splits** | 2026-10-14 | A stock-split ledger. The packet format was already stable |
| ⚡ **GoldAccountManager 0.1** | 2026-10-29 | The packet idea generalized for any app, ported to Go, plus attestations and app isolation |

### 🔁 What carried over

- ✅ Plain JSON owned by the user, with the same honest limits stated up front
- ✅ Random identity labels and **revision lineage**
- ✅ Safe parsing: size limits, whitelisted fields, bounded values
- ✅ The **canonical-JSON SHA-256 checksum**. The Go port is tested against vectors produced by Payout Lab's JavaScript, so checksums match across both languages
- ✅ A small, dependency-free design system (Payout Lab's *Green Ion* became the seed for [Blue Bolt UI](#-blue-bolt-ui))

### 🆕 What changed

| | Payout Lab packet | Gold packet |
|---|---|---|
| Language | JavaScript, in the browser | Go core and services, with a JavaScript browser reader planned |
| File | `.payout` · `payout-packet` | `.gold` · `gold-packet` |
| Identity | `portfolioId` (`pf_`) | `packetId` (`pk_`) **plus `appId`** |
| Content | Typed holdings, settings, reports | A generic `payload` each app validates itself |
| Isolation | One app | A packet only opens in its own app |
| Trust | Checksum only | Checksum **plus signed attestations** |
| Field names | Exact match | Case variants rejected (fuzzing found a Go/JS mismatch) |

**Not ported yet:** snapshot links, QR cards, saved-report receipts and CSV import. Encrypted packets and passkey unlock keys are on both projects' roadmaps.

📜 Read more on the [History page](https://sukonik.github.io/GoldAccountManager/history.html).

---

## 🧱 Three tiers

Each app picks how much server it needs.

| Tier | What exists | Cost | Good for |
|---|---|---|---|
| 🥇 **0 · Packet only** | The packet (a file plus an on-device copy). No sign-up, no phone, no email | **$0** | Utility apps, preferences, tools |
| 🥈 **1 · Verified packet** | Tier 0 plus a tiny service that confirms an email or phone once and signs an attestation | Small. SMS only if a paid rung is used | Apps needing real identity or recovery |
| 🥉 **2 · Hosted account** | A normal server-side record, with the packet as export and backup | Real, capped by per-app quotas | Apps whose server holds the data, such as matching and messaging |

📱 **Which of your apps fit where:** utility apps → Tier 0 · legal software (offline) → Tier 0/1 with signed offline grants · dating app → Tier 2.

---

## ✅ Free-first verification

> 💬 **There is no free outbound SMS.** Carriers charge for every code you send. So the approach is not a trick. It is to **avoid sending**, using the cheapest method the user already has.

### 🪜 The ladder, cheapest first

| Rung | How it confirms | Cost |
|---|---|---|
| 0️⃣ **Verify later** | Works with no confirmation. Ask only for recovery, sync or a paid feature | $0 |
| 1️⃣ **Google sign-in** | A verified email from a Google ID token | Free |
| 2️⃣ **Email the user sends** | The user sends *us* a code, so **we send nothing** | $0 if inbound mail is free |
| 2️⃣b **Email magic link** | We email a link | Free tiers have daily limits |
| 3️⃣ **Telegram contact share** | A bot button returns the user's own number | Bot API reported free |
| 4️⃣ **WhatsApp, user first** | The user messages us first, and replies in 24 hours are reported free | Reported free, may change |
| 5️⃣ **SMS code** | We send a code | 💰 Per message. **Off by default on free plans** |

⚠️ Prices were gathered from third-party sources. **Re-check every vendor's own page** before budgeting. Carrier email-to-text gateways (like `number@txt.att.net`) are reported shut down or unreliable, so we don't build on them.

### 🔏 Confirm once, attest forever

After any rung succeeds, the server signs a short attestation that rides in the packet:

- 🙈 **No address or number inside.** The subject is an HMAC under an app-specific secret, so the same person in two apps gets unrelated subjects. *(Someone holding every key could still link them, so the promise depends on trusting the operator.)*
- 🔒 **Cannot be moved.** The signature covers the app id and packet id, so a copied attestation reports `bad-signature`.
- 🏷️ **The method is signed.** An app can require a passkey for one action and accept an email link for another.
- 🔑 **Passkeys after the first confirmation**, so later sign-ins send no codes.

📘 More: [`docs/verification.md`](docs/verification.md) and the [Verification page](https://sukonik.github.io/GoldAccountManager/verification.html).

---

## 🧰 Use it from Go

Needs **Go 1.24+** for the libraries and `goldd`. The module has **no third-party dependencies**. To build the docs site, use a current Go release (see [Quality checks](#-quality-checks)).

```go
import (
	"github.com/sukonik/goldaccountmanager/packet"
	"github.com/sukonik/goldaccountmanager/verify"
)
```

### 📦 Create, save and open a packet

```go
now := time.Now()
p, _ := packet.New("notes-demo", "Sam's notes", packet.AppInfo{Name: "Notes Demo", Version: "0.1.0"}, now)
p.Payload = json.RawMessage(`{"theme":"dark"}`)
file, _ := p.Marshal() // write this to disk: it is the user's account

opened, warnings, err := packet.Parse(file, packet.ParseOptions{
	ExpectAppID: "notes-demo", // keeps accounts isolated per app
	ValidatePayload: func(raw json.RawMessage) (json.RawMessage, error) {
		// rebuild the payload from whitelisted fields, or reject it
		return raw, nil
	},
})
```

### 🌿 Compare two copies

```go
switch packet.Compare(local, incoming) {
case packet.IncomingNewer: // continue from it
case packet.Diverged:      // both changed: offer packet.AsSeparateCopy(...)
}
```

### ✍️ Attest a confirmed email, and check it later

```go
email, _ := verify.Normalize(packet.KindEmail, "Sam@Example.com")
subject, _ := verify.Subject(appSecret, p.AppID, packet.KindEmail, email)
att, _ := signer.Attest(p.AppID, p.PacketID, packet.KindEmail, packet.MethodEmailReply, subject, now, now.AddDate(1, 0, 0))
p.Attestations = append(p.Attestations, att)

checker := verify.NewChecker(map[string]ed25519.PublicKey{"k1": signer.PublicKey()})
if verify.Has(checker.Check(p, time.Now()), packet.KindEmail) {
	// a valid, unexpired email confirmation
}
```

▶️ Runnable examples live in the package docs: `go doc ./packet` and `go doc ./verify`.

---

## 💻 Command line

```bash
go run ./cmd/goldd packet new   -app notes-demo -name "Sam's notes" -o sam.gold
go run ./cmd/goldd packet check -app notes-demo sam.gold
go run ./cmd/goldd version
```

| Exit code | Meaning |
|---|---|
| `0` | ✅ Packet is valid |
| `1` | ❌ Rejected (not a packet, wrong app, bad value…) |
| `2` | ❓ Bad usage |
| `3` | ⚠️ Valid, but with a warning such as `checksum_mismatch` |

Files written by `packet new -o` are created with mode `0600`, because a packet is private to its owner.

---

## 🎨 Blue Bolt UI

**Blue Bolt UI** is the small, dependency-free design system used by this project's docs and future apps: one CSS file and one optional script, in [`site/assets/`](site/assets).

- 🌗 Light and dark themes that follow the device, with a manual toggle
- 🏷️ **Plain HTML looks right with no classes.** `bb-` classes only add variants and layout
- 🎯 Role-based color tokens and a spacing scale of 2, 4, 8, 12, 16, 24, 32, 40, 48, 64, 80, 96 px
- ♿ **WCAG 2.2 AA checked numerically** (36 text, boundary and focus pairs across both themes), 44 px controls, a 2 px focus ring, `prefers-reduced-motion`, `forced-colors` and print styles
- 📵 Works without JavaScript

### 🔗 Where the ideas come from

No code was copied. Licenses are in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

| Reference | Idea taken |
|---|---|
| 🟢 **[Green Ion](https://github.com/Sukonik/payout-lab)** (Payout Lab) | Device-following themes, press feedback, a single-file design system |
| 🌾 **[oat](https://github.com/knadh/oat)** (MIT) | Semantic HTML first, minimal classes |
| 🔷 **[Carbon](https://github.com/carbon-design-system/carbon)** (Apache-2.0) | Role-based tokens, spacing scale, 2 px focus ring with 3:1 contrast |
| 🪙 **[GoldBrief UI/UX](https://sukonik.github.io/goldbrief/ui-ux.html)** | Native controls before libraries, a checklist of every UI state, testing from 320 to 1920 px. More to borrow in later updates |

> 🧭 **Not yet verified:** the site hasn't been tested with a screen reader, on a physical phone, or in Safari and Firefox. It has been checked in Chromium at 320, 390 and 1280 px for horizontal overflow and theme switching.

🖼️ Live kit: [Blue Bolt UI page](https://sukonik.github.io/GoldAccountManager/blue-bolt.html)

---

## 🧪 Quality checks

| Check | Result at this commit |
|---|---|
| 🧪 `go test -race ./...` | ✅ Passing |
| 🔀 **Cross-language checksums** | ✅ Match Payout Lab's JavaScript on three vectors (numbers, strings, nesting) |
| 🐛 **Fuzzing** (`FuzzParse`) | 🔧 Found **two real bugs**, both fixed and kept as regression tests: a crash on `"lineage": []`, and case-insensitive field names |
| 🧹 `golangci-lint` (incl. `gosec`, `errorlint`, `revive`) | ✅ 0 issues |
| 🛡️ `govulncheck` | ✅ **Libraries and `goldd`: clean on every Go version tried** (after removing `net/mail`, which had 3 reported issues, in favor of a small strict email validator). The docs build tool `sitegen` is affected by standard-library issues in `html/template` and `os` on older Go (8 on Go 1.24.7 and 1.25.1, 2 on 1.25.13) and is **clean on Go 1.26.9**. CI uses the latest stable Go |
| 🔗 Site link checker | ✅ Every internal link and anchor resolves, one `h1` per page |
| 🌐 Browser check | ✅ No overflow at 320, 390, 1280 px. Theme toggle works |

Go review checklists came from [samber/cc-skills-golang](https://github.com/samber/cc-skills-golang) (security, error handling, testing, code style).

---

## 🗺️ Roadmap

| Phase | Status | Focus |
|---|---|---|
| **0 · Foundations** | ✅ Done | Packet format, attestations, `goldd`, CI, docs site, Blue Bolt UI |
| **1 · Confirmation and sessions** | 🔜 Next | Real channels (magic link, reply email, Google), a small attestation server with per-app quotas and rate limits, long sessions with refresh rotation and a grace window, a JavaScript browser reader, demo mode |
| **2 · Encryption and passkeys** | 📅 Planned | Passkey-encrypted packets (before any private data), WebAuthn, Telegram and WhatsApp channels, a capped paid SMS channel |
| **3 · Hosted tier and offline** | 📅 Planned | Server-side accounts for data-heavy apps, signed offline grants, per-app plans and billing |

**🚫 Deliberately not included:** one account shared across apps · acting as a sign-in provider for outside developers · a full SAML/enterprise single sign-on stack (use something like Keycloak).

---

## 📚 All resources

### 📖 This project

| Resource | What it is |
|---|---|
| 🌐 [Documentation site](https://sukonik.github.io/GoldAccountManager/) | Latest version · [all versions](https://sukonik.github.io/GoldAccountManager/versions.html) |
| 📘 [`docs/packet-format.md`](docs/packet-format.md) | The normative packet specification |
| 📘 [`docs/verification.md`](docs/verification.md) | Verification summary |
| 🎯 [`SCOPE.md`](SCOPE.md) | **The current decisions**, which win if other planning notes disagree |
| 🧩 [`FEATURES.md`](FEATURES.md) | The long feature wishlist and per-feature upstream references |
| 🗓️ [`PLAN.md`](PLAN.md) | Phase plan and architecture |
| 🔬 [`RESEARCH.md`](RESEARCH.md) | Auth-engine comparison, the Payout Lab analysis and the verification ladder |
| 🔐 [`SECURITY.md`](SECURITY.md) | Reporting vulnerabilities and known limits |
| ⚖️ [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) | Licenses and attributions |
| 🤝 [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to contribute and release a site version |

### 🧪 Origin

| Resource | What it is |
|---|---|
| [Payout Lab](https://github.com/Sukonik/payout-lab) · [live site](https://sukonik.github.io/payout-lab/) | Where packets started |
| [Payout Lab packet format](https://github.com/Sukonik/payout-lab/blob/main/docs/packet-format.md) | The format this one descends from |
| [Payout Lab links doc](https://github.com/Sukonik/payout-lab/blob/main/docs/links.md) | Snapshot links, a later feature to port |

### 🏛️ Open-source identity projects studied

| Project | Learned from it |
|---|---|
| [Keycloak](https://github.com/keycloak/keycloak) | Realms, admin UX, required actions, protocol coverage |
| [Ory Kratos](https://github.com/ory/kratos) · [Hydra](https://github.com/ory/hydra) · [Keto](https://github.com/ory/keto) | Self-service flows, identity schemas, OAuth2, relationship permissions |
| [Zitadel](https://github.com/zitadel/zitadel) | Event sourcing, organizations. ⚖️ AGPL: ideas only, **never copy code** |
| [Casdoor](https://github.com/casdoor/casdoor) · [Casbin](https://github.com/casbin/casbin) | Provider catalog, UI-first admin, policy engine |
| [SuperTokens](https://github.com/supertokens/supertokens-core) | Refresh rotation with theft detection, recipes and overrides |
| [Authentik](https://github.com/goauthentik/authentik) | Flows and stages |
| [go-webauthn](https://github.com/go-webauthn/webauthn) · [pquerna/otp](https://github.com/pquerna/otp) | Planned passkey and TOTP libraries |

### 🆚 Hosted and library options compared

[Better Auth](https://better-auth.com/docs/plugins) · [Supabase Auth](https://supabase.com/docs/guides/auth) · [Neon Auth](https://neon.com/docs/changelog/2025-12-12) · [Clerk](https://clerk.com/pricing) · [Auth0](https://auth0.com/pricing) · [Appwrite](https://appwrite.io/alternative-to/auth0) · [Firebase Auth](https://firebase.google.com/pricing)

📝 Free-tier numbers in [`RESEARCH.md`](RESEARCH.md) are from third-party sources. **Verify on each vendor's own page.**

### 🎨 Design and quality references

| | |
|---|---|
| 🌾 [oat](https://github.com/knadh/oat) · 🔷 [Carbon](https://github.com/carbon-design-system/carbon) · 🪙 [GoldBrief UI/UX](https://sukonik.github.io/goldbrief/ui-ux.html) | UI references for [Blue Bolt UI](#-blue-bolt-ui) |
| 🐹 [samber/cc-skills-golang](https://github.com/samber/cc-skills-golang) · [skills.sh Go skills](https://www.skills.sh/?q=go) | Go review checklists: [security](https://www.skills.sh/samber/cc-skills-golang/golang-security), [error handling](https://www.skills.sh/samber/cc-skills-golang/golang-error-handling), [testing](https://www.skills.sh/samber/cc-skills-golang/golang-testing), [code style](https://www.skills.sh/samber/cc-skills-golang/golang-code-style), [design patterns](https://www.skills.sh/samber/cc-skills-golang/golang-design-patterns), [performance](https://www.skills.sh/samber/cc-skills-golang/golang-performance), [database](https://www.skills.sh/samber/cc-skills-golang/golang-database), [documentation](https://www.skills.sh/samber/cc-skills-golang/golang-documentation), [modernize](https://www.skills.sh/samber/cc-skills-golang/golang-modernize) |

---

## 🗃️ Project layout

```
GoldAccountManager/
├── packet/            # the packet format: parse, marshal, compare, canonical JSON
├── verify/            # keyed subjects, signed attestations, confirmation channels
├── cmd/
│   ├── goldd/         # command line: packet new, packet check
│   └── sitegen/       # builds the docs site from site/ into docs/
├── site/              # docs site sources
│   ├── pages/         # page fragments
│   ├── assets/        # Blue Bolt UI: blue-bolt.css, blue-bolt.js, favicon
│   ├── examples/      # real .gold files, kept valid by tests
│   ├── layout.html    # shared page layout
│   ├── VERSION        # current site version
│   └── versions.json  # every released site version
├── docs/              # built site served by GitHub Pages, plus the specs
│   └── v0.1/          # 📌 preserved build of site version 0.1.0
├── .github/workflows/ # CI: tests, race detector, fuzz, lint, vulnerability scan, docs check
└── *.md               # SCOPE, FEATURES, PLAN, RESEARCH, SECURITY, CONTRIBUTING, notices
```

---

## 🛠️ Development

```bash
go test -race ./...                       # tests
go vet ./... && golangci-lint run ./...   # static checks
govulncheck ./...                         # known vulnerabilities
go test ./packet -run '^$' -fuzz FuzzParse -fuzztime 30s   # fuzz the parser
go run ./cmd/sitegen                      # rebuild the docs site into docs/
go run ./cmd/sitegen -check               # fail if docs/ is out of date (CI does this)
go run ./cmd/sitegen -snapshot v0.2       # also write a preserved build, when releasing a site version
```

🚢 **Releasing a site version:** bump [`site/VERSION`](site/VERSION), add an entry to [`site/versions.json`](site/versions.json), run `go run ./cmd/sitegen -snapshot vX.Y`, and commit `docs/`. Preserved folders are never edited afterwards. A test fails if a listed version has no preserved build.

---

## 🤝 Contributing

Feedback on [`SCOPE.md`](SCOPE.md) and the [roadmap](#-roadmap) is the most useful thing right now: open an issue with questions, objections or missing requirements. Code contributions: read [`CONTRIBUTING.md`](CONTRIBUTING.md). 🔐 Report vulnerabilities privately, see [`SECURITY.md`](SECURITY.md).

## 📄 License

Licensed under the [Mozilla Public License 2.0](LICENSE). Derived from ideas and a format proven in [Payout Lab](https://github.com/Sukonik/payout-lab), also MPL-2.0.
