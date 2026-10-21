# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ |

## Reporting a vulnerability

Email: **security@2mny.com** (or open a private security advisory on this repo:
Security tab → "Report a vulnerability").

Please include: reproduction steps, affected file(s), impact assessment. We
respond within 72 hours and credit reporters in release notes unless you
prefer to stay anonymous.

## Design principles this codebase is held to

1. **Read-only lookups only.** Every outbound call is a GET/POST question to a
   public API. No exploit code, no credential stuffing, no scraping infrastructure.
2. **Honest three-state verdicts** — exposed / clear / unavailable. A source that
   cannot answer is never counted as "clear".
3. **Identifiers are never stored raw** — salted hashes + masked display forms only;
   password checks store no result rows at all (k-anonymity, client-side match).
4. **Per-source failure isolation** — one broken source degrades one card, never a check.
5. **No third-party JavaScript, no analytics, no tracking.** The dashboard is self-contained.
6. **HTTPS-only outbound** (enforced by CI test on every source's request specs).

## Scope notes for researchers

- The admin session cookie is `http_only` + `same_site=lax`. Login is throttled (5 attempts / 5 min / IP).
- CSRF is enforced on every state-changing route (Laravel defaults).
- The display-image proxy (`/osint-logo/*`) is path-traversal-guarded, throttled, and
  caches only validated image bytes (magic-number checked) — it cannot be used as an
  open proxy or SSRF vector (fixed allow-list of source-registered domains).
- The license client is intentionally readable and makes exactly three kinds of calls
  (activate / validate / heartbeat) to one configurable host over HTTPS.
