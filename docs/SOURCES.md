# Data Sources — all 22, all keyless

Every source below is **free, keyless (no API key, no account), read-only, and queried over HTTPS**.
Per-source enable/disable lives on the Settings page. Attribution and limits are listed honestly —
if a source is down, its card shows `unavailable` and the check continues (per-source isolation).

| # | Source | Category | Checks | Endpoint / data | Notes |
|---|--------|----------|--------|-----------------|-------|
| 1 | HudsonRock | stealer | email | `cavalier.hudsonrock.com` infostealer corpus | Stealer-log infections linked to the email (counts + machine info only; no raw cookies) |
| 2 | XposedOrNot | breach | email | `api.xposedornot.com/v1/breach-analytics` | Which breaches contain the email (names, dates, record counts) |
| 3 | ProxyNova COMB | breach | email, phone | `api.proxynova.com/comb` | 11B+ credential-pair COMB corpus association (masked, credential lines never stored) |
| 4 | HIBP Pwned Passwords | breach | password | `api.pwnedpasswords.com/range/{5-hex}` | k-anonymity: only the 5-char SHA-1 prefix leaves this server; suffix matching happens in YOUR browser |
| 5 | Mailcheck | email | email | `mailcheck.ai/domain/` | Domain deliverability + disposable classification |
| 6 | Gravatar | profile | email | `gravatar.com` | Public avatar + profile existence |
| 7 | Disposable Email Domains list | email | email | `disposable-email-domains` blocklist (GitHub) | One-time/temp provider domain flag |
| 8 | Disify | email | email | `disify.com/api/email/` | Disposable/validity signal |
| 9 | Kickbox Open | email | email | `open.kickbox.com/v1/disposable/` | Disposable signal (open endpoint) |
| 10 | FachaTemp | email | email | `api.facha.dev/v1/temporary-email/` | Temp-provider domain signal |
| 11 | Presend | email, phone | email, phone | `presend.pages.dev/api/` | Deliverability + phone lookups |
| 12 | GitHub public search | profile | email, username | `api.github.com` (unauthenticated) | Public code/profile associations |
| 13 | Maigret corpus (150 sites) | profile | username | Local `storage/app/maigret/sites.json` + live site probes | Username registered on N of 150 popular platforms — rendered as the platform logo grid. Corpus: maigret (MIT) + WhatsMyName (CC BY-SA 4.0), differential-verified |
| 14 | Bluesky (AT Protocol) | profile | username | `public.api.bsky.app` | Handle/profile existence |
| 15 | Hacker News (Firebase) | profile | username | `hacker-news.firebaseio.com` | Public HN account existence + karma |
| 16 | PhoneValidity | infra | phone | E.164 parsing (libphonenumber semantics, in-process) | Country, line type, validity — no external call |
| 17 | Shodan InternetDB | infra | ip | `internetdb.shodan.io` (keyless) | Open ports + services on the IP |
| 18 | ipapi.is | infra | ip | `api.ipapi.is` (keyless) | VPN/proxy/hosting classification |
| 19 | Bot-CIDR attribution | infra | ip | offline crawler-network ranges (CrawlerScope-inspired) | Is the IP a known crawler/bot network — offline, no external call |
| 20 | crt.sh — Certificate Transparency | infra | domain | `crt.sh/?q=%.{domain}` (keyless) | Historical subdomains that ever obtained a TLS certificate — counts + first 40 names |
| 21 | RDAP — Domain Registration Records | infra | domain | `rdap.org/domain/{domain}` (keyless) | Registrar, registration/expiry dates, status — registration age as a fraud/trust signal |
| 22 | LeakLens | breach | phone, username | `leaklens.org/api/mcp` (keyless JSON-RPC tools/call) | Breach-registry search for phone numbers and usernames; honest `unavailable` when upstreams degrade |

## Display images

Platform favicons and Gravatar avatars are fetched once per platform by the in-repo
`OsintLogoService` (24h negative cache, 5s budget per fetch) and served from
`/osint-logo/{key}` and `/osint-avatar/gravatar/{hash}`. A missing image falls back to a
letter tile — never blocks a result.

## Deliberately NOT in the Community Edition

- **GrayHatWarfare** — bucket search (the hosted 2mny.com version uses an owner API key; the CE stays 100% keyless)
- **Domain / website checks** — that is the job of the
  [Website Vulnerability Scanner CE](https://github.com/RanaKhan77/Website-Vulnerability-Scanner) (200 modules).
  Domain intelligence lives in the main scanner engine instead: the hosted platform's
  `org_breach_history` module reports an organization's documented data-breach history from
  the **LeakLens registry** — [leaklens.org](https://leaklens.org), free for non-commercial
  use, attribution required and given. The CE stays personal-identifiers-only.
- **holehe binary** — the hosted product runs it internally (GPLv3, run-not-redistributed); the CE stays license-clean without it
- **The ~120-platform linked-account probe** — v1.1 roadmap: it needs a companion headless-browser microservice (the same one the hosted product runs); ships as an optional Docker add-on, never as a hard dependency
- **Telegram / WhatsApp lookups** — require bot keys and risk account bans (fail the keyless + safe-to-operate bar)

## Adding a source

Implement `App\Modules\Osint\Sources\OsintSource` (two methods: `requests()` + `parse()`), register
the class in `OsintCheckService::SOURCES`, add a row here. The contract is documented inline in
`app/Modules/Osint/Sources/OsintSource.php` — including the non-negotiable ethical rules (never
return plaintext credentials, never return third-party personal data, always degrade to
`unavailable` on failure).
