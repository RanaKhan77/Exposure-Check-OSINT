<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

/**
 * Contract for one OSINT data source adapter (2MNY Trace / Exposure Check).
 *
 * Two-phase design so the orchestrator can fan out ALL supporting sources in
 * a single Http::pool (parallel, one wall-clock budget):
 *   1. requests()  - declare the HTTP calls this source needs for a check
 *   2. parse()     - turn the pooled responses into a display result
 *
 * Check types: email | username | phone | password | domain | ip.
 * For type=password the identifier is ONLY the 5-hex SHA-1 prefix of the
 * password (k-anonymity) - the plaintext password never reaches this server.
 *
 * Result contract (from parse()):
 *   status   : 'hit' | 'clean' | 'unavailable'
 *   summary  : one-line human sentence (shown on the collapsed card)
 *   data     : array of display fields (key => value; may nest one level)
 *   severity : 'critical' | 'high' | 'medium' | 'low' | 'info' (default 'info')
 *
 * ETHICAL RULES (non-negotiable, enforced per source):
 *   - NEVER return plaintext passwords or credential lines to the client.
 *   - NEVER return third-party personal data (names/emails of other people);
 *     aggregate counts + dates + classifications only.
 *   - Every upstream call must carry a short timeout and degrade to
 *     status='unavailable' on any transport failure (never fake a clean pass).
 */
interface OsintSource
{
    /** Stable source key, snake_case (used as pool prefix + card identity). */
    public function key(): string;

    /** Human display label. */
    public function label(): string;

    /** Card category: stealer | breach | profile | reputation | infra | email. */
    public function category(): string;

    /** Does this source support the given check type? */
    public function supports(string $type): bool;

    /**
     * Declare HTTP requests for this check.
     * @return array<int, array{name: string, method: 'GET'|'POST', url: string, headers?: array<string, string>, body?: array<string, mixed>|string}>
     */
    public function requests(string $type, string $identifier): array;

    /**
     * Parse this source's responses (only names returned by requests()).
     * @param array<string, \Illuminate\Http\Client\Response> $responses
     * @return array{status: string, summary: string, data: array<string, mixed>, severity?: string}
     */
    public function parse(string $type, string $identifier, array $responses): array;
}
