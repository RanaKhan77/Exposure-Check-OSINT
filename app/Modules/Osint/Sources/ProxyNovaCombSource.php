<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * ProxyNova COMB search v2.0 — keyless credential-pair dataset search.
 * GET https://api.proxynova.com/comb?query={target}&start=0&limit=100
 * Returns {"count":N,"lines":["identifier:password",...]} (hard API cap:
 * 100 lines per query, no pagination past 100 — verified live 2026-10-20).
 *
 * v2.0 (2026-10-20, owner directive "ProxyNova-style, as addon with the
 * scanner system"): for a PERSONAL identifier (email / username / phone)
 * the card now returns the actual leaked credential pairs. The UI masks
 * every password by default and offers a per-line reveal toggle — same
 * capability as proxynova.com/tools/comb, but shoulder-surfing safe.
 *
 * ETHICS MODEL (per-identifier split, hard policy):
 *   - email / username / phone (the requester's own identifier):
 *       credential lines ARE returned (identifier + password). The owner
 *       checking their own address is the entire point of the tool, and
 *       the password side is masked in the UI until explicitly revealed.
 *   - domain (org-wide view — pairs belong to EMPLOYEES, not the
 *       requester): counts + MASKED emails only. Passwords and full
 *       credential lines are NEVER returned for domain queries; the org
 *       owner can verify each address individually in Exposure Check.
 *   - Nothing is logged; the controller strips credential_lines before
 *       persisting the audit row (OsintCheckService::sanitizeForStorage).
 *
 * Matching semantics (COMB is a substring search — verified live):
 *   - email    : identifier part (before first ':') case-insensitively
 *                EQUALS the email. "john@gmail.com:" (blank password)
 *                still counts — the address is in the dump either way.
 *   - username : identifier equals the username, or starts with
 *                username+'@' (dump formats store "user@provider").
 *   - phone    : up to 3 searched forms (digits, US dashed, +1 dashed —
 *                verified live: "2024561111" finds nothing while
 *                "202-456-1111" and "1-202-456-1111" hit). A line can
 *                expose the number as a LOGIN ("202-456-1111@bk.ru:pw")
 *                or as a PASSWORD someone chose — those are split into
 *                as_username pairs (shown) and as_password_count (count
 *                only: those lines carry a THIRD PARTY's email+password).
 *   - domain   : identifier part ends with '@'+domain.
 */
class ProxyNovaCombSource implements OsintSource
{
    private const URL = 'https://api.proxynova.com/comb';
    /** Hard API cap — verified live ("You are limited to 100 results"). */
    private const LIMIT = 100;
    /** Credential lines returned to the UI (masked + reveal there). */
    private const LINES_SHOWN = 10;
    /** Max chars we ever carry per identifier / password fragment. */
    private const FIELD_CAP = 96;

    public function key(): string
    {
        return 'proxynova';
    }

    public function label(): string
    {
        return 'COMB Credential Dataset (11B+ records)';
    }

    public function category(): string
    {
        return 'breach';
    }

    public function supports(string $type): bool
    {
        return in_array($type, ['email', 'username', 'phone', 'domain'], true);
    }

    /** @return array<int,array<string,mixed>> */
    public function requests(string $type, string $identifier): array
    {
        $q = rawurlencode($identifier);

        if ($type === 'phone') {
            $reqs = [];
            foreach ($this->phoneForms($identifier) as $i => $form) {
                $reqs[] = [
                    'name' => $this->key() . '.phone' . $i,
                    'method' => 'GET',
                    'url' => self::URL . '?query=' . rawurlencode($form) . '&start=0&limit=' . self::LIMIT,
                    'headers' => ['Accept' => 'application/json'],
                ];
            }

            return $reqs;
        }

        return [
            [
                'name' => $this->key() . '.main',
                'method' => 'GET',
                'url' => self::URL . '?query=' . $q . '&start=0&limit=' . self::LIMIT,
                'headers' => ['Accept' => 'application/json'],
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        if ($type === 'phone') {
            return $this->parsePhone($identifier, $responses);
        }

        $resp = $responses[$this->key() . '.main'] ?? null;
        if (!$resp instanceof Response || !$resp->ok()) {
            return ['status' => 'unavailable', 'summary' => 'Credential dataset search unavailable right now.', 'data' => []];
        }

        $json = $resp->json();
        $lines = is_array($json) && is_array($json['lines'] ?? null) ? $json['lines'] : [];
        if ($lines === []) {
            return $this->clean('No credential pairs found in the COMB dataset.');
        }

        if ($type === 'email') {
            return $this->parseEmail($identifier, $lines);
        }
        if ($type === 'username') {
            return $this->parseUsername($identifier, $lines);
        }
        if ($type === 'domain') {
            return $this->parseDomain($identifier, $lines);
        }

        return $this->clean('No credential pairs found in the COMB dataset.');
    }

    // ── type parsers ────────────────────────────────────────────────

    /** @param array<int,mixed> $lines */
    private function parseEmail(string $email, array $lines): array
    {
        $needle = strtolower($email);
        $matched = [];
        foreach ($lines as $line) {
            if (!is_string($line)) {
                continue;
            }
            [$ident, $pass] = $this->splitLine($line);
            if ($ident === '' || strtolower($ident) !== $needle) {
                continue;
            }
            $matched[] = [$ident, $pass];
        }

        return $this->pairsResult($matched, count($lines), $this->maskEmailLocal($email));
    }

    /** @param array<int,mixed> $lines */
    private function parseUsername(string $username, array $lines): array
    {
        $needle = strtolower($username);
        $matched = [];
        foreach ($lines as $line) {
            if (!is_string($line)) {
                continue;
            }
            [$ident, $pass] = $this->splitLine($line);
            $low = strtolower($ident);
            if ($ident === '' || ($low !== $needle && !str_starts_with($low, $needle . '@'))) {
                continue;
            }
            $matched[] = [$ident, $pass];
        }

        return $this->pairsResult($matched, count($lines), $username);
    }

    /**
     * Phone: merge all searched forms, split as-username (pairs shown) vs
     * as-password (count only — third-party credentials).
     */
    private function parsePhone(string $digits, array $responses): array
    {
        $forms = $this->phoneForms($digits);
        $lines = [];
        foreach ($forms as $i => $form) {
            $resp = $responses[$this->key() . '.phone' . $i] ?? null;
            if (!$resp instanceof Response || !$resp->ok()) {
                continue;
            }
            $json = $resp->json();
            $batch = is_array($json) && is_array($json['lines'] ?? null) ? $json['lines'] : [];
            foreach ($batch as $line) {
                if (is_string($line)) {
                    $lines[trim($line)] = true; // dedup across forms
                }
            }
        }
        if ($lines === []) {
            $ok = collect($responses)->filter(fn ($r) => $r instanceof Response && $r->ok())->count() > 0;

            return $ok
                ? $this->clean('No credential pairs found for this phone number.')
                : ['status' => 'unavailable', 'summary' => 'Credential dataset search unavailable right now.', 'data' => []];
        }

        $lowForms = array_map('strtolower', $forms);
        $asUser = [];
        $asPass = 0;
        foreach (array_keys($lines) as $line) {
            [$ident, $pass] = $this->splitLine((string) $line);
            $lowIdent = strtolower($ident);
            $lowPass = strtolower($pass);
            $isUser = false;
            foreach ($lowForms as $f) {
                if ($f !== '' && (str_contains($lowIdent, $f) || str_starts_with($lowIdent, $f))) {
                    $isUser = true;
                    break;
                }
            }
            if ($isUser) {
                $asUser[] = [$ident, $pass];
                continue;
            }
            foreach ($lowForms as $f) {
                if ($f !== '' && str_contains($lowPass, $f)) {
                    $asPass++;
                    break;
                }
            }
        }

        $total = count($asUser) + $asPass;
        if ($total <= 0) {
            return $this->clean('No credential pairs found for this phone number.');
        }

        $data = [
            'pairs_found' => $total,
            'dataset' => $this->datasetName(),
            'searched_forms' => $forms,
            'note' => 'The number appears in dumped credential pairs — as a login name and/or as someone\'s chosen password (both mean the digits are public).',
        ];
        if ($asPass > 0) {
            $data['as_password_count'] = $asPass . ' pair(s) where the number itself was used as a password (owner of those accounts is someone else — their details stay hidden)';
        }

        $out = $this->pairsResult($asUser, count($lines), $digits, $total);
        // merge the phone-specific context (searched forms / as-password
        // count / note) into the shared pairsResult shape — pairsResult
        // builds its own data array, so without this merge they were lost
        $out['data'] = array_merge($out['data'], $data);
        $out['data']['pairs_found'] = $total;

        return $out;
    }

    /**
     * Domain: counts + MASKED emails only — never passwords (those lines
     * belong to the organization's people, and the requester may not be
     * the owner; the owner verifies each address individually instead).
     *
     * @param array<int,mixed> $lines
     */
    private function parseDomain(string $domain, array $lines): array
    {
        $needle = '@' . strtolower($domain);
        $pairs = 0;
        $emails = [];
        foreach ($lines as $line) {
            if (!is_string($line)) {
                continue;
            }
            [$ident] = $this->splitLine($line);
            $low = strtolower($ident);
            // well-formed addresses only (dump lines can carry junk)
            if ($ident === '' || !str_ends_with($low, $needle)
                || !preg_match('/^[a-z0-9._%+\-]{1,64}@' . preg_quote(strtolower($domain), '/') . '$/', $low)) {
                continue;
            }
            $pairs++;
            $emails[$low] = true;
        }
        $emails = array_keys($emails);
        sort($emails);

        if ($pairs <= 0) {
            return $this->clean('No leaked credentials found for addresses at this domain.');
        }

        $masked = array_map(fn (string $e) => $this->maskEmailLocal($e), array_slice($emails, 0, 10));

        return [
            'status' => 'hit',
            'summary' => 'EXPOSED — ' . count($emails) . ' address(es) at this domain with ' . $pairs . ' leaked credential pair(s) in breach collections. Passwords are never shown for domain checks — verify each address individually in Exposure Check.',
            'severity' => 'critical',
            'data' => [
                'pairs_found' => $pairs,
                'emails_found' => count($emails),
                'masked_emails' => $masked,
                'dataset' => $this->datasetName(),
                'note' => 'Addresses are masked here on purpose: run each one through the email check to see its own credential detail. API caps the sweep at 100 pairs per query, so counts may be higher.',
            ],
        ];
    }

    // ── helpers ─────────────────────────────────────────────────────

    /**
     * Shared shape for email / username / phone-as-user results.
     *
     * @param array<int,array{0:string,1:string}> $matched
     */
    private function pairsResult(array $matched, int $scanned, string $who, ?int $overrideTotal = null): array
    {
        $total = $overrideTotal ?? count($matched);
        if ($total <= 0) {
            return $this->clean('No credential pairs found in the COMB dataset.');
        }

        $capped = count($matched) >= self::LIMIT && $scanned >= self::LIMIT;
        $lines = [];
        foreach (array_slice($matched, 0, self::LINES_SHOWN) as [$ident, $pass]) {
            $lines[] = [
                'identifier' => $ident,
                'password' => $pass,
            ];
        }

        $data = [
            'pairs_found' => $total,
            'credential_lines' => $lines,
            'lines_shown' => count($lines),
            'dataset' => $this->datasetName(),
            'passwords' => 'masked — click the eye to reveal one; change this password everywhere it was reused',
        ];
        if ($capped) {
            $data['pairs_capped'] = 'the dataset returned the API maximum (100 rows) — the true count may be higher';
        }

        return [
            'status' => 'hit',
            'summary' => 'EXPOSED — ' . $total . ' leaked credential pair(s) for this identifier in breach collections. Passwords are masked below; reveal to verify and change them everywhere.',
            'severity' => 'critical',
            'data' => $data,
        ];
    }

    /** @return array{0:string,1:string} */
    private function splitLine(string $line): array
    {
        $line = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', trim($line)) ?? '';
        $pos = strpos($line, ':');
        if ($pos === false) {
            return [mb_substr($line, 0, self::FIELD_CAP), ''];
        }
        $ident = trim(mb_substr($line, 0, $pos));
        $pass = mb_substr($line, $pos + 1);

        return [mb_substr($ident, 0, self::FIELD_CAP), mb_substr($pass, 0, self::FIELD_CAP)];
    }

    /**
     * Searched phone forms (verified live 2026-10-20):
     *   - 10 digits        → digits + "XXX-XXX-XXXX"
     *   - 11 digits "1..." → digits + "1-XXX-XXX-XXXX" + "XXX-XXX-XXXX"
     *   - 11 digits "0..." → digits (BD/local form) + "XXX-XXXX-XXXX"
     *   - anything else    → digits only
     *
     * @return array<int,string>
     */
    private function phoneForms(string $digits): array
    {
        $digits = preg_replace('/\D+/', '', $digits) ?? '';
        if ($digits === '') {
            return [];
        }
        $forms = [$digits];
        $n = strlen($digits);
        if ($n === 10) {
            $forms[] = substr($digits, 0, 3) . '-' . substr($digits, 3, 3) . '-' . substr($digits, 6);
        } elseif ($n === 11 && $digits[0] === '1') {
            $forms[] = '1-' . substr($digits, 1, 3) . '-' . substr($digits, 4, 3) . '-' . substr($digits, 7);
            $forms[] = substr($digits, 1, 3) . '-' . substr($digits, 4, 3) . '-' . substr($digits, 7);
        } elseif ($n === 11 && $digits[0] === '0') {
            $forms[] = substr($digits, 0, 3) . '-' . substr($digits, 3, 4) . '-' . substr($digits, 7);
        }

        return array_values(array_unique($forms));
    }

    /** j***n@gmail.com — enough for the owner to recognize their own address. */
    private function maskEmailLocal(string $email): string
    {
        $at = strrpos($email, '@');
        if ($at === false || $at === 0) {
            return $email;
        }
        $local = substr($email, 0, $at);
        $domain = substr($email, $at);
        if (mb_strlen($local) <= 2) {
            return mb_substr($local, 0, 1) . '***' . $domain;
        }

        return mb_substr($local, 0, 1) . '***' . mb_substr($local, -1, 1) . $domain;
    }

    private function datasetName(): string
    {
        return 'COMB / Collection #1-5 (aggregated breach collections via ProxyNova)';
    }

    /** @return array<string,mixed> */
    private function clean(string $summary): array
    {
        return [
            'status' => 'clean',
            'summary' => $summary,
            'severity' => 'info',
            'data' => [
                'pairs_found' => 0,
                'dataset' => $this->datasetName(),
                'note' => 'Searched 11B+ aggregated credential records (Collection #1-5 + COMB). API caps each search at 100 rows.',
            ],
        ];
    }
}
