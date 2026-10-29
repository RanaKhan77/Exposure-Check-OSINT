# Privacy — what leaves this server, exactly

This page is the honest, complete list. If it is not listed here, it does not happen.

## What is stored locally (and only locally)

| Data | Where | Form |
|------|-------|------|
| Check history | `exposure_checks` table (SQLite on your machine) | Type + **salted SHA-256 hash** of the identifier + masked display form (`j***n@gmail.com`) + aggregated results. The raw identifier is **never** stored. |
| Password checks | nothing | Password checks store **no result rows at all** — matching happens in your browser |
| Settings, license state | local tables | Quotas, toggles, license key |
| Platform logos cache | `storage/app/osint-logos` | Public favicons, cache only, purgeable |

Delete any record from the History page, or **Purge all** — one click, gone.

## What leaves the server, and to whom

1. **The identifier you type** (email/username/phone/IP) — sent over HTTPS to the
   keyless OSINT sources listed in [SOURCES.md](SOURCES.md), because that is
   literally what a lookup is. Each source sees only what it needs.
2. **For password checks: only the first 5 hex chars of the SHA-1** (k-anonymity).
   Not the password. Not the full hash. See [CHECKS.md](CHECKS.md#4-password-exposure-).
3. **License network calls** — ONLY when you explicitly activate, refresh or deactivate a
   free key on the license page (payload: key, random install ID, domain, version — to
   `2mny.com`). This powers the voluntary install counter and free update notifications.
   It carries **no check data and no identifiers**. There is **no scheduled heartbeat by
   default** (v2, Oct 2026): the daily heartbeat cron was removed; operators who want to
   appear on the public install map can opt in with `LICENSE_HEARTBEAT=on`. The whole
   license client is ~300 readable lines: `app/Services/CommunityLicenseService.php`.

## What is deliberately NOT collected

- No analytics, no tracking pixels, no third-party JavaScript
- No raw identifiers in any log (audit rows store hashes + masked forms only)
- No credential material in the database (`credential_lines` are stripped before storage)
- No telemetry beyond the explicit license actions above (and none at all unless you
  activate a key; the heartbeat is opt-in only)

## Threat-model honesty

- The OSINT sources themselves learn that *someone at your IP* checked a given
  identifier — that is inherent to any lookup tool, hosted or self-hosted. Running
  this yourself means the *results* never touch anyone else's server.
- The result cache (30 min default, configurable) is keyed by a SHA-1 of
  type + identifier and stored in your local cache store only.
