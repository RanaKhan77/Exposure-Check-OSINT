# FAQ

## Does my password ever leave my machine?

No. Your browser hashes it with SHA-1 locally and sends only the **first 5 hex characters**
of that hash. The server fetches the hash-suffix range for that prefix from HIBP's free
Pwned Passwords API and returns it; your browser does the final match locally. The full
hash — and the password itself — never reach the server. This is the same k-anonymity
design used by 1Password, Bitwarden and haveibeenpwned.com's password check.

## Can I check someone else's email/phone/username?

The tool is for checking **identifiers you are authorized to assess** — yours, or your
organization's with permission. The README and this FAQ say it plainly: using exposure
data to harass, dox or attack people is abuse, and the tool gives you aggregate counts
and public-record signals, not ammunition.

## Why is domain/website scanning not included?

Scope discipline. Domain/website vulnerability scanning is a different job with a
different engine — ours ships as the
[Website Vulnerability Scanner Community Edition](https://github.com/RanaKhan77/Website-Vulnerability-Scanner)
(202 scanner modules, same license philosophy). The two repos cross-link each other.

## Is this an AI tool?

No. Zero AI, zero ML, zero external "smart" services. Every check is a deterministic,
reproducible HTTP lookup with honest three-state verdicts (exposed / clear / unavailable).
If a source is down, the card says so instead of guessing. That is a feature.

## Why do some cards say "unavailable"?

Honesty over theater. Public APIs rate-limit, change, or hiccup. A source that could not
answer is shown as `unavailable` — it does NOT count as "clear", and it does not kill the
rest of the check (per-source isolation). Re-run the check to retry.

## Where does the data come from?

22 keyless public sources — breach databases (XposedOrNot, HIBP Pwned Passwords),
infostealer corpus (HudsonRock), the COMB credential corpus (ProxyNova), disposable-email
databases, the Maigret/WhatsMyName 150-site username corpus, Bluesky, Hacker News, GitHub
public search, Shodan InternetDB, ipapi.is and more. Full table with attribution:
[SOURCES.md](SOURCES.md).

## Can I turn sources off?

Yes — Settings page → per-source toggles. Disabled sources are never contacted.

## Is it really self-hosted with no API keys?

Yes. Every source in the Community Edition is keyless. Clone, `./install.sh`, sign in,
check. The only optional outbound call beyond the lookups is the free community license
heartbeat (see [PRIVACY.md](PRIVACY.md)) — and the license code is short and auditable.

## How is this different from holehe / mosint / sherlock?

Those are good tools (some now unmaintained) that each cover one slice — holehe:
email→registered-website accounts; sherlock/maigret: username→platforms. Exposure-Check-OSINT
covers email **and** username **and** phone **and** password **and** IP in one self-hosted
dashboard with an honest exposure score, history, printable reports and per-source
verdicts. It is a maintained, complete product rather than a CLI one-trick pass.

## What license is this?

Apache-2.0 (application code). The username site corpus carries upstream attribution
(maigret MIT, WhatsMyName CC BY-SA 4.0) — see `storage/app/maigret/sites.json` header.
Full details in the [LICENSE](../LICENSE) file and [SOURCES.md](SOURCES.md).
