# Changelog

All notable changes to Exposure-Check-OSINT are documented here.

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
