<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * mailcheck.ai - keyless email-domain intelligence.
 * GET https://mailcheck.ai/domain/{domain} -> {domain_age_in_days, mx, mx_records,
 * mx_providers, spf, dmarc, disposable, public_domain, relay_domain,
 * free_subdomain, spam, did_you_mean}
 *
 * Used for both email checks (deliverability + disposable detection) and
 * domain checks (mail hardening posture at a glance).
 */
class MailcheckSource implements OsintSource
{
    private const URL = 'https://mailcheck.ai/domain/';

    public function key(): string
    {
        return 'mailcheck';
    }

    public function label(): string
    {
        return 'Mailcheck — Email Domain Intelligence';
    }

    public function category(): string
    {
        return 'email';
    }

    public function supports(string $type): bool
    {
        return in_array($type, ['email', 'domain'], true);
    }

    public function requests(string $type, string $identifier): array
    {
        $domain = $type === 'email'
            ? strtolower(substr(strrchr($identifier, '@') ?: '', 1))
            : strtolower($identifier);
        if ($domain === '' || !filter_var($domain, FILTER_VALIDATE_DOMAIN)) {
            return [];
        }

        return [
            [
                'name' => $this->key() . '.main',
                'method' => 'GET',
                'url' => self::URL . urlencode($domain),
                'headers' => ['Accept' => 'application/json'],
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $resp = $responses[$this->key() . '.main'] ?? null;
        if (!$resp instanceof Response || !$resp->ok()) {
            return ['status' => 'unavailable', 'summary' => 'Email domain intelligence unavailable right now.', 'data' => []];
        }

        $j = $resp->json();
        if (!is_array($j)) {
            return ['status' => 'unavailable', 'summary' => 'Email domain intelligence returned an unexpected response.', 'data' => []];
        }

        $disposable = (bool) ($j['disposable'] ?? false);
        $mx = (bool) ($j['mx'] ?? false);
        $spam = (bool) ($j['spam'] ?? false);
        $age = (int) ($j['domain_age_in_days'] ?? 0);
        $dym = (string) ($j['did_you_mean'] ?? '');

        $flags = [];
        if ($disposable) {
            $flags[] = 'disposable/temporary email provider';
        }
        if (!$mx) {
            $flags[] = 'no MX records (cannot receive mail)';
        }
        if ($spam) {
            $flags[] = 'flagged as spam-associated domain';
        }

        $data = [
            'disposable' => $disposable,
            'mx_present' => $mx,
            'spam_flagged' => $spam,
            'domain_age_days' => $age,
            'spf' => (bool) ($j['spf'] ?? false),
            'dmarc' => (bool) ($j['dmarc'] ?? false),
            'mx_providers' => is_array($j['mx_providers'] ?? null) ? array_slice($j['mx_providers'], 0, 4) : [],
        ];
        if ($dym !== '') {
            $data['did_you_mean'] = $dym;
        }

        if ($flags !== []) {
            return [
                'status' => 'hit',
                'summary' => 'Email domain concerns: ' . implode('; ', $flags) . '.',
                'severity' => $disposable ? 'medium' : 'low',
                'data' => $data,
            ];
        }

        return [
            'status' => 'clean',
            'summary' => 'Email domain looks healthy'
                . ($age > 0 ? ' (domain age ' . number_format($age) . ' days)' : '')
                . ($data['spf'] && $data['dmarc'] ? ' with SPF+DMARC published' : '') . '.',
            'severity' => 'info',
            'data' => $data,
        ];
    }
}
