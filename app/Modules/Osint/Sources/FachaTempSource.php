<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * FachaAPI temporary-email (api.facha.dev) - keyless disposable corroboration.
 * GET https://api.facha.dev/v1/temporary-email/{domain} -> {"temporary":bool}
 *
 * Third independent disposable verdict (domain-level), completing the
 * Disify + Kickbox + Facha 3-way corroboration chain. R6-B live-verified
 * 2026-10-20.
 */
class FachaTempSource implements OsintSource
{
    private const URL = 'https://api.facha.dev/v1/temporary-email/';

    public function key(): string
    {
        return 'facha_temp';
    }

    public function label(): string
    {
        return 'FachaAPI — Temporary Email Check';
    }

    public function category(): string
    {
        return 'email';
    }

    public function supports(string $type): bool
    {
        return $type === 'email';
    }

    public function requests(string $type, string $identifier): array
    {
        $domain = strtolower(substr(strrchr($identifier, '@') ?: '', 1));
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
            return ['status' => 'unavailable', 'summary' => 'FachaAPI temporary-email check unavailable right now.', 'data' => []];
        }

        $j = $resp->json();
        if (!is_array($j) || !array_key_exists('temporary', $j)) {
            return ['status' => 'unavailable', 'summary' => 'FachaAPI returned an unexpected response.', 'data' => []];
        }

        $temporary = (bool) $j['temporary'];

        if ($temporary) {
            return [
                'status' => 'hit',
                'severity' => 'medium',
                'summary' => 'FachaAPI lists this email domain as a temporary/throwaway provider.',
                'data' => ['temporary' => true],
            ];
        }

        return [
            'status' => 'clean',
            'severity' => 'info',
            'summary' => 'FachaAPI: domain is not a known temporary email provider.',
            'data' => ['temporary' => false],
        ];
    }
}
