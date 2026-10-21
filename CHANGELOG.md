# Changelog

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
