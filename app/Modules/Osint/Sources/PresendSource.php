<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * Presend (presend.pages.dev) - keyless multi-tool suite (best-effort).
 *
 *   email  -> GET /api/email-verify?email={email}
 *             {"syntax_valid":bool,"has_mx":bool,"disposable":bool,
 *              "role_account":bool,"valid":bool,"reason":?string}
 *   domain -> GET /api/email-security?domain={domain}
 *             {"domain":...,"score":0-100,"verdict":string,
 *              "spf":{...},"dmarc":{"policy":...,"enforced":bool},
 *              "dkim":{"checked_selectors":N,"found_selectors":[...]}}
 *   phone  -> GET /api/phone-verify?number={E164}
 *             {"number":...,"valid":bool,"country":"BD",
 *              "country_calling_code":"880","type":"Unknown","formats":{...}}
 *
 * Hobby-grade pages.dev service: every failure degrades to
 * status='unavailable' — it is never the sole source for a signal
 * (Disify/Kickbox/Facha corroborate disposable; Mailcheck corroborates
 * mail posture; PhoneValiditySource corroborates phone). R6-B
 * live-verified 2026-10-20.
 */
class PresendSource implements OsintSource
{
    private const BASE = 'https://presend.pages.dev/api/';

    public function key(): string
    {
        return 'presend';
    }

    public function label(): string
    {
        return 'Presend — Verify & Email-Security Suite';
    }

    public function category(): string
    {
        return 'email';
    }

    public function supports(string $type): bool
    {
        return in_array($type, ['email', 'domain', 'phone'], true);
    }

    public function requests(string $type, string $identifier): array
    {
        if ($type === 'email' && filter_var($identifier, FILTER_VALIDATE_EMAIL)) {
            return [[
                'name' => $this->key() . '.email',
                'method' => 'GET',
                'url' => self::BASE . 'email-verify?email=' . urlencode($identifier),
                'headers' => ['Accept' => 'application/json'],
            ]];
        }
        if ($type === 'domain' && filter_var($identifier, FILTER_VALIDATE_DOMAIN)) {
            return [[
                'name' => $this->key() . '.security',
                'method' => 'GET',
                'url' => self::BASE . 'email-security?domain=' . urlencode(strtolower($identifier)),
                'headers' => ['Accept' => 'application/json'],
            ]];
        }
        if ($type === 'phone') {
            $e164 = preg_replace('/[^0-9+]/', '', $identifier);
            if ($e164 !== '' && $e164[0] !== '+') {
                $e164 = '+' . $e164;
            }
            if (strlen($e164) >= 8) {
                return [[
                    'name' => $this->key() . '.phone',
                    'method' => 'GET',
                    'url' => self::BASE . 'phone-verify?number=' . urlencode($e164),
                    'headers' => ['Accept' => 'application/json'],
                ]];
            }
        }

        return [];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        if ($type === 'email') {
            return $this->parseEmail($responses);
        }
        if ($type === 'domain') {
            return $this->parseSecurity($responses);
        }
        if ($type === 'phone') {
            return $this->parsePhone($responses);
        }

        return ['status' => 'unavailable', 'summary' => 'Unsupported check type.', 'data' => []];
    }

    /** @param array<string, Response> $responses */
    private function parseEmail(array $responses): array
    {
        $resp = $responses[$this->key() . '.email'] ?? null;
        if (!$resp instanceof Response || !$resp->ok()) {
            return ['status' => 'unavailable', 'summary' => 'Presend email verification unavailable right now.', 'data' => []];
        }
        $j = $resp->json();
        if (!is_array($j)) {
            return ['status' => 'unavailable', 'summary' => 'Presend returned an unexpected response.', 'data' => []];
        }

        $valid = (bool) ($j['valid'] ?? false);
        $disposable = (bool) ($j['disposable'] ?? false);
        $role = (bool) ($j['role_account'] ?? false);
        $mx = (bool) ($j['has_mx'] ?? false);
        $reason = isset($j['reason']) && is_string($j['reason']) ? $j['reason'] : '';

        $data = [
            'syntax_valid' => (bool) ($j['syntax_valid'] ?? false),
            'has_mx' => $mx,
            'disposable' => $disposable,
            'role_account' => $role,
            'valid' => $valid,
        ];

        if ($disposable) {
            return [
                'status' => 'hit',
                'severity' => 'medium',
                'summary' => 'Presend: disposable email address' . ($reason !== '' ? ' (' . $reason . ')' : '') . '.',
                'data' => $data,
            ];
        }
        if (!$valid) {
            return [
                'status' => 'hit',
                'severity' => 'low',
                'summary' => 'Presend: address looks undeliverable' . ($reason !== '' ? ' — ' . $reason : '') . '.',
                'data' => $data,
            ];
        }

        return [
            'status' => 'clean',
            'severity' => 'info',
            'summary' => 'Presend: valid, deliverable address'
                . ($mx ? ' with MX records' : '')
                . ($role ? ' (role/group mailbox)' : '') . '.',
            'data' => $data,
        ];
    }

    /** @param array<string, Response> $responses */
    private function parseSecurity(array $responses): array
    {
        $resp = $responses[$this->key() . '.security'] ?? null;
        if (!$resp instanceof Response || !$resp->ok()) {
            return ['status' => 'unavailable', 'summary' => 'Presend email-security check unavailable right now.', 'data' => []];
        }
        $j = $resp->json();
        if (!is_array($j) || !isset($j['score'])) {
            return ['status' => 'unavailable', 'summary' => 'Presend returned an unexpected response.', 'data' => []];
        }

        $score = max(0, min(100, (int) $j['score']));
        $verdict = isset($j['verdict']) && is_string($j['verdict']) ? $j['verdict'] : '';
        $dmarc = is_array($j['dmarc'] ?? null) ? $j['dmarc'] : [];
        $dkim = is_array($j['dkim'] ?? null) ? $j['dkim'] : [];
        $spf = is_array($j['spf'] ?? null) ? $j['spf'] : [];

        $data = [
            'score' => $score,
            'verdict' => $verdict,
            'dmarc_policy' => isset($dmarc['policy']) ? (string) $dmarc['policy'] : null,
            'dmarc_enforced' => (bool) ($dmarc['enforced'] ?? false),
            'spf_present' => (bool) ($spf['present'] ?? ($spf !== [])),
            'dkim_selectors_found' => is_array($dkim['found_selectors'] ?? null)
                ? array_slice(array_map('strval', $dkim['found_selectors']), 0, 5)
                : [],
            'dkim_selectors_checked' => (int) ($dkim['checked_selectors'] ?? 0),
        ];

        if ($score < 50) {
            return [
                'status' => 'hit',
                'severity' => 'medium',
                'summary' => sprintf(
                    'Presend: weak email-spoofing protections on this domain (score %d/100)%s.',
                    $score,
                    $verdict !== '' ? ' — ' . rtrim($verdict, '.') : ''
                ),
                'data' => $data,
            ];
        }
        if ($score < 80) {
            return [
                'status' => 'hit',
                'severity' => 'low',
                'summary' => sprintf(
                    'Presend: partially protected against email spoofing (score %d/100)%s.',
                    $score,
                    $verdict !== '' ? ' — ' . rtrim($verdict, '.') : ''
                ),
                'data' => $data,
            ];
        }

        return [
            'status' => 'clean',
            'severity' => 'info',
            'summary' => sprintf(
                'Presend: well protected against email spoofing (score %d/100)%s.',
                $score,
                $data['dmarc_policy'] !== null ? ' — DMARC policy ' . $data['dmarc_policy'] : ''
            ),
            'data' => $data,
        ];
    }

    /** @param array<string, Response> $responses */
    private function parsePhone(array $responses): array
    {
        $resp = $responses[$this->key() . '.phone'] ?? null;
        if (!$resp instanceof Response || !$resp->ok()) {
            return ['status' => 'unavailable', 'summary' => 'Presend phone verification unavailable right now.', 'data' => []];
        }
        $j = $resp->json();
        if (!is_array($j) || !array_key_exists('valid', $j)) {
            return ['status' => 'unavailable', 'summary' => 'Presend returned an unexpected response.', 'data' => []];
        }

        $valid = (bool) $j['valid'];
        $country = isset($j['country']) && is_string($j['country']) ? $j['country'] : '';
        $data = [
            'valid' => $valid,
            'country' => $country,
            'country_calling_code' => isset($j['country_calling_code']) ? (string) $j['country_calling_code'] : '',
            'e164' => isset($j['number']) ? (string) $j['number'] : '',
        ];

        if (!$valid) {
            return [
                'status' => 'hit',
                'severity' => 'low',
                'summary' => 'Presend: this number does not look like a valid phone number.',
                'data' => $data,
            ];
        }

        return [
            'status' => 'clean',
            'severity' => 'info',
            'summary' => 'Presend: valid phone number'
                . ($country !== '' ? ' registered in ' . $country : '') . '.',
            'data' => $data,
        ];
    }
}
