<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Cache;

/**
 * Disposable-email-domain blocklist (community-maintained, CC0-ish).
 * Source list: disposable-email-domains/disposable_email_blocklist.conf on
 * GitHub (raw). We cache the full list for 24h and match the email domain
 * locally - zero external request per check after the first load.
 */
class DisposableEmailSource implements OsintSource
{
    private const LIST_URL = 'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf';
    private const CACHE_KEY = 'osint.disposable.list.v1';

    public function key(): string
    {
        return 'disposable';
    }

    public function label(): string
    {
        return 'Disposable Email Detection';
    }

    public function category(): string
    {
        return 'reputation';
    }

    public function supports(string $type): bool
    {
        return $type === 'email';
    }

    public function requests(string $type, string $identifier): array
    {
        // Local list only - no per-check HTTP request. We still participate in
        // the pool round-trip with a self-request against our own health ping
        // to keep orchestrator bookkeeping uniform (0 external calls).
        return [];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $domain = strtolower(substr(strrchr($identifier, '@') ?: '', 1));
        if ($domain === '') {
            return ['status' => 'unavailable', 'summary' => 'Invalid email address.', 'data' => []];
        }

        $list = Cache::remember(self::CACHE_KEY, 86400, function (): array {
            try {
                $body = (string) \Illuminate\Support\Facades\Http::timeout(10)->get(self::LIST_URL)->body();
                $list = array_filter(array_map('trim', explode("\n", $body)));
                sort($list);

                return array_flip($list);
            } catch (\Throwable $e) {
                return [];
            }
        });

        if ($list === []) {
            return ['status' => 'unavailable', 'summary' => 'Disposable-domain list unavailable right now.', 'data' => []];
        }

        // Check the domain and its registrable-parent (handles subdomain tricks).
        $isDisposable = isset($list[$domain]);
        if (!$isDisposable && substr_count($domain, '.') > 1) {
            $parts = explode('.', $domain);
            array_shift($parts);
            $isDisposable = isset($list[implode('.', $parts)]);
        }

        if ($isDisposable) {
            return [
                'status' => 'hit',
                'summary' => 'This is a disposable/temporary email domain — accounts using it are often auto-rejected or flagged.',
                'severity' => 'low',
                'data' => ['disposable' => true, 'domain' => $domain],
            ];
        }

        return [
            'status' => 'clean',
            'summary' => 'Not a known disposable/temporary email domain.',
            'severity' => 'info',
            'data' => ['disposable' => false, 'domain' => $domain],
        ];
    }
}
