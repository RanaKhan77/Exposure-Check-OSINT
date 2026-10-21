# Changelog

All notable changes to Exposure-Check-OSINT are documented here.

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
