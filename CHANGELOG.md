# Changelog

## [1.7.0] — 2026-10-29

### Sources — W58 OSINT repo deep-pass, round 2

- **Source 24: Keybase linked identities** — the identity-graph pivot: one keyless
  lookup returns the account's deliberately-public verified proofs (Twitter,
  GitHub, Reddit, HackerNews, DNS domains, PGP fingerprint). A bare account is a
  low-severity footprint; 3+ verified links is a real deanonymization surface
  (medium). Documented 205 semantics for missing users; verified proofs
  (`state=1`) only — unverified claims never count.
- **Source 25: GitHub commit author-email pivot** — the reverse of the existing
  github_public email check: given a USERNAME, which real addresses did it author
  public commits with (e.g. `torvalds@…`)? Addresses are MASKED (`t***s@…`);
  noreply-only accounts report good hygiene; and the card carries the PROBABLE
  caveat the adoption review required — git author fields are spoofable, so a
  match is evidence of exposure, not proof. Zero-match semantics live-verified:
  qualifier-only author searches 422 on zero matches -> clean, never unavailable.
- **Maigret corpus 150 -> 200 sites** — 290 fresh WhatsMyName candidates,
  differential-self-checked (claimed vs unclaimed username) from the production
  egress IP: 136 passed, top 50 selected by platform recognition and category
  priority, with platform-family dedup (Mastodon instances capped, adult sites
  excluded, already-covered platforms skipped). ArtStation, Bandcamp, Dribbble,
  metacritic, cnet, freesound, Genius, IFTTT and more join the grid.

## [1.6.0] — 2026-10-29

### Sources — W58 OSINT adoption research

- **Source 23: DNS blocklist reputation** (Spamhaus ZEN, SpamCop, Barracuda) — the one
  keyless personal-IP signal the CE was missing: "is MY IP listed as a spam/abuse
  source?" (compromised device, hijacked router, prior abuse). Pure DNS queries
  (no HTTP, no keys), same offline-source pattern as Bot-CIDR.
- **Honest-degradation design (live-verified in production):** DNSBL refusals are
  ambiguous — Spamhaus sometimes answers open/public-resolver queries with
  127.255.255.x error codes and sometimes with EMPTY answers. Each zone is therefore
  probed first with the permanently-listed test address 127.0.0.2; a zone whose test
  probe does not demonstrably return a listing is reported `not assessed`, never a
  fake clean. IPv6 and restricted resolvers degrade honestly too.
- **Adoption research** (dual independent model reviews over omnisint, PublicEye,
  n1xYosint, osint-toolbox-mcp, Consensus-OSINT, tiktok-scraper + awesome lists):
  DNSBL (adopt, CE) and selective Maigret-corpus expansion (follow-up) were the two
  clear keyless + personal + license-safe wins. Crypto-address checks, TikTok,
  ORCID and Wayback were evaluated and deliberately deferred or rejected (weak
  exposure semantics, fragility, or keyless-availability risk) — reasoning kept in
  the W58 research notes.

## [1.5.0] — 2026-10-29

### Licensing — v2 "No Wall" (same policy as the scanner CE)

- **The 14-day trial wall is GONE.** Every check, source, report and export works
  forever with no key, no countdown and no phone-home. v1 blocked new checks after a
  14-day trial unless a free Community key was activated; that wall contradicted the
  "free forever" promise and was removed across the codebase.
- `CommunityLicenseService` v2: `status()` is now purely informational
  (`licensed` / `unlicensed` / `key-revoked` — no `trial`, `grace` or `blocked`
  states); `checksAllowed()` always returns true (kept for blade/route compatibility).
  The optional free key powers exactly two things: the aggregate install counter and
  free premium update notifications.
- **Zero telemetry by default.** The daily heartbeat and weekly re-validation schedules
  were removed from `routes/console.php`. The license client only talks to the server
  when you explicitly activate, refresh or deactivate a key. Opt-in heartbeat for the
  public install map: `LICENSE_HEARTBEAT=on` (off by default).
- Key revocation now only stops update notifications — checks keep working.
- `EnsureCommunityLicensed` middleware never blocks; it shows a once-per-session hint
  about the optional free key.
- License page rebuilt for v2 (no trial countdown, no "blocked" chip); README,
  `docs/PRIVACY.md`, `docs/FAQ.md` and `docs/SELF-HOSTING.md` updated to match.

### Maintenance

- CI: `actions/checkout` v4 → v7 (dependabot #4).
- Version constant synced (`config/app.php` 1.1.0 → 1.5.0 — it had drifted from the
  changelog).
- Note: the print-ready PDFs in `pdfs/` still describe the v1 trial policy for the
  license sections; they will be regenerated in a follow-up release (the markdown
  docs are authoritative).

## [1.4.0] — 2026-10-23

### Sources

- **Source 22: LeakLens breach-registry search (phone + username)** — keyless
  MCP endpoint (`leaklens.org/api/mcp`, stateless JSON-RPC `tools/call`).
  First **phone breach-exposure** source (PhoneValidity only checks E.164
  validity) and a breach-flavored complement to the Maigret platform-presence
  grid for usernames. 21 → 22 keyless sources across README, badge, docs and
  composer description; the dashboard count stays registry-derived.
- **Deliberate scope**: no email (XposedOrNot already queries the same upstream
  corpus directly), no password (the LeakLens audit endpoint is an HIBP range
  proxy; PwnedPasswordsSource queries HIBP directly and the browser-side
  k-anonymity matcher is keyed to it), no domain (EC surfaces domain
  infrastructure only — crt.sh + RDAP; website scanning stays in the scanner CE).
- **Honest degradation** (their semantics meet ours): `isExposed:false` with
  `degraded:true` maps to `unavailable`, never a fake clean; hits record which
  upstreams did not answer. Result items are reduced to aggregates (breach
  name, date, record count) — credential-like and third-party-identity fields
  are dropped before anything reaches the client.
- License note: leaklens.org registry data is free for non-commercial, civic
  and human-rights use — fine for this self-hosted personal checker; not
  licensed for the commercial platform (this source ships CE-only, by design).
- New dedicated unit test (`LeakLensSourceTest`, 10 cases, mocked MCP
  envelopes — hit/clean/degraded/isError/transport/malformed/cap/ethics).

## [1.3.1] — 2026-10-23

### Fixed

- **v1.3.0 follow-up — the two new sources were shipped but not wired.** v1.3.0 added
  `CrtShSource` and `RdapSource` as files and updated every count claim to 21, but the
  `OsintCheckService::SOURCES` registry still listed 19, so the dashboard rendered
  "19 keyless sources" while the README said 21, and the new sources never ran. Both
  are now registered, the `domain` check type is live (mirroring the hosted product),
  and every count is registry-derived again. The domain check surfaces a domain's
  public infrastructure footprint only (CT-log subdomain history via crt.sh, registry
  records via RDAP) — website vulnerability scanning stays in the scanner CE.
- Domain normalization is stricter than the hosted product: `FILTER_VALIDATE_DOMAIN`
  alone accepts spaces and underscores, so the CE requires a dot-joined hostname
  shape (and strips scheme, path and port). "not a domain" now 422s honestly.
- The scope-rule test (`test_check_types_do_not_include_domain`) became
  `test_check_types_include_domain_infra`: the 5-check identity is now 6 checks
  (email, username, phone, password, domain, ip). README, docs/CHECKS.md and the
  dashboard tabs/placeholder/auto-detect updated in the same commit.

## [1.3.0] — 2026-10-23

### Sources
- **Sources 20–21: crt.sh certificate transparency + RDAP domain registration records** — both keyless, both free public services; 19 → 21 keyless sources across README, badge, docs and composer description. CI continues to derive the count from the source registry.

## [1.2.1] — 2026-10-22

### Security
- **PHP base image now builds against PHP 8.3.36** (released 2026-10-21, fixes
  CVE-2026-109618 and CVE-2026-109619, the "PHP2Shell" unauthenticated RCE pair,
  CVSS v4.0 9.2). The Dockerfile uses the floating "php:8.3-apache" tag, so any
  image built after 2026-10-21 automatically includes the fixed runtime; no
  Dockerfile change was needed. Self-hosters: pull + rebuild + restart Apache.
- CI now derives the keyless-source count from the source registry (the stale
  hardcoded count broke CI after v1.2.0).


## [1.2.0] — 2026-10-21

### Added
- **19th source: Bot CIDR Attribution** (offline, zero requests) — IP checks now
  say whether the IP belongs to an operator-published crawler network range
  (Googlebot, Bingbot, Meta crawler, Applebot). In-range traffic is verifiable
  crawler traffic; OUT-of-range traffic claiming those user-agents is spoofed.
  Includes the operator-documented reverse-DNS verification hint per range.
  Inspired by CrawlerScope research (S32).

### Changed
- Source count 18 → 19 across README, dashboard copy, Docker label and FAQ.

All notable changes to Exposure-Check-OSINT are documented here.

## [1.1.0] — 2026-10-21

### Added
- **JSON / CSV export** — every stored check can now be downloaded as a JSON
  document (full per-source detail) or a flat CSV (one row per source verdict)
  from the report page, the history table and right after a live check.
  Exports keep identifiers masked and re-strip credential material
  belt-and-braces, exactly like the stored rows.
- **`php artisan ec:doctor`** — install self-test: PHP version and required
  extensions, app key, admin password, storage writability, maigret site
  database validity, database + migration state, source-registry health, and
  a live reachability probe for all 18 sources (parallel, short timeout).
  Table output by default, structured JSON with `--json`; non-zero exit code
  when anything FAILs. Run it after install and any time results look wrong.
- **Username confidence tiers** — every username hit is now labeled
  `confirmed` (page-content or redirect verified) or `probable`
  (status-code only) — on the dashboard logo grid, in the report table and
  in the JSON/CSV exports. Older stored checks render without badges
  (graceful degradation).

### Fixed
- Reported version: `config/app.version` was still `1.0.0` inside the
  v1.0.1 release — now bumped correctly (report header shows v1.1.0).

## [1.0.1] — 2026-10-21

### Fixed
- Report page: the exposure score now shows its scale (`X / 100`, 100 = clean)
  and a prominent risk label (`CRITICAL EXPOSURE` / `ELEVATED` / `MINOR` /
  `LOW` / `NO EXPOSURE FOUND`). Previously a bare `0` was ambiguous — readers
  could mistake maximum exposure for "no exposure".
- Dashboard: the daily-quota chip no longer renders as a stray empty pill
  before the first check of the day (`[hidden]` display guard added).
- Logout now fully destroys the session record (`invalidate()` +
  `regenerateToken()`); `regenerate()` alone kept the old session alive
  until expiry.
- Privacy contract: IP addresses are now masked in stored reports
  (`103.***.***.12`, IPv6 first+last group) — previously the raw IP was
  stored, violating the "identifiers never stored raw" promise.

### Changed
- README screenshots replaced with REAL live-product captures (dashboard,
  live results view with score gauge, printable report) — no mockups.

### Verified
- Full AI-assisted security review (seed-2-0-pro): 2 real findings fixed
  (both above); 4 other reported findings verified false and documented
  (Laravel 11 auto-CSRF; identical rate-limiter keys; registry-whitelisted
  logo proxy; quota consumed only on success).
- CI green: PHP 8.2 / 8.3 / 8.4 matrix, lint + contract tests + Docker
  build-context verification.

## [1.0.0] — 2026-10-21

### Added
- Initial Community Edition release.
- 5 check types: email, username, phone, password (k-anonymity), IP.
- 18 keyless source adapters extracted from the 2MNY production engine with
  per-source failure isolation. (The ~120-platform linked-account probe is
  v1.1: it requires the optional browser-service add-on.)
- Single-admin dashboard: parallel check page with platform logo grid,
  exposure score gauge, category sections, honest three-state verdicts.
- History with per-record delete + purge-all (identifiers stored as salted
  hashes + masked forms only; password checks store no rows).
- Printable HTML report (browser print -> PDF; no server-side PDF dependency).
- Settings page: daily quota, burst limit, cache TTL, honest UA string,
  per-source enable/disable.
- Community license (14-day trial -> free key from 2mny.com, weekly
  re-validation, 7-day offline grace) — product code `exposure-check`.
- One-command Docker install (Apache + PHP 8.3 + SQLite, single container).
- Contract test suite (interface, key uniqueness, HTTPS-only specs,
  normalization, masking, credential-line stripping) + GitHub Actions CI
  (PHP 8.2/8.3/8.4 matrix, lint every file).

### Security
- Password flow regression-fixed from day one: only the 5-hex SHA-1 prefix
  is accepted (the production Oct-20 rewrite had broken this contract).
- Display-image proxy is path-traversal-guarded and domain-registered.
