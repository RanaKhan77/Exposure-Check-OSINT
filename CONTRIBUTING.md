# Contributing

Thanks for helping — this project keeps three promises, and every contribution
must keep them too:

1. **Keyless only.** New sources must work with zero API keys, zero accounts,
   zero cost. If it needs a key, it belongs in the hosted product, not the CE.
2. **Read-only only.** Every request the engine sends must be a question to a
   public API. No exploit code, no credential stuffing, no scraping infrastructure,
   no "recon" that creates load or risk for third parties.
3. **Honest verdicts.** A source that cannot answer is `unavailable` — never
   counted as "clear". Evidence before claims.

## Adding a source

1. Read `app/Modules/Osint/Sources/OsintSource.php` (the contract + ethical rules).
2. Implement the class in `app/Modules/Osint/Sources/` (two-phase: `requests()` + `parse()`).
3. Register it in `OsintCheckService::SOURCES`.
4. Add a row to `docs/SOURCES.md` with endpoint, license/ToS note and limits.
5. `vendor/bin/phpunit` must pass (contract tests cover the new class automatically).

## Bug reports

Include: what you ran, what came back, the exact source card text, your PHP/Docker
version. Screenshots help. Check the [FAQ](docs/FAQ.md) first — "unavailable" cards
are usually an upstream hiccup, re-run the check.

## Code style

PHP 8.2+, `declare(strict_types=1)`, ASCII-only in code, comments explain WHY.
The CI lints every file on three PHP versions — keep it green.
