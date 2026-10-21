<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * HIBP Pwned Passwords k-anonymity range API (free, keyless, forever per Troy Hunt).
 *
 * Flow: the CLIENT hashes the password with SHA-1 and sends us only the first
 * 5 hex chars. We fetch the suffix list for that range from
 * https://api.pwnedpasswords.com/range/{PREFIX} and return the raw
 * SUFFIX35:COUNT lines so the CLIENT matches its full hash locally.
 * The full password hash — and the password itself — never reach us.
 *
 * With Add-Padding the response includes random zero-count decoys (privacy).
 */
class PwnedPasswordsSource implements OsintSource
{
    private const URL = 'https://api.pwnedpasswords.com/range/';

    public function key(): string
    {
        return 'pwnedpasswords';
    }

    public function label(): string
    {
        return 'HIBP Pwned Passwords (k-anonymity)';
    }

    public function category(): string
    {
        return 'breach';
    }

    public function supports(string $type): bool
    {
        return $type === 'password';
    }

    public function requests(string $type, string $identifier): array
    {
        // identifier = 5 uppercase hex chars (validated by the controller)
        return [
            [
                'name' => $this->key() . '.main',
                'method' => 'GET',
                'url' => self::URL . strtoupper($identifier),
                'headers' => ['Add-Padding' => 'true'],
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $resp = $responses[$this->key() . '.main'] ?? null;
        if (!$resp instanceof Response || !$resp->ok()) {
            return ['status' => 'unavailable', 'summary' => 'Password exposure database unavailable right now.', 'data' => []];
        }

        $body = trim((string) $resp->body());
        if ($body === '') {
            return ['status' => 'unavailable', 'summary' => 'Password exposure database returned no data.', 'data' => []];
        }

        // Hand the whole suffix list to the client — matching happens locally.
        return [
            'status' => 'clean', // final verdict is computed client-side
            'summary' => 'Range fetched — matching happens in your browser (k-anonymity: your password never left this device).',
            'severity' => 'info',
            'data' => [
                'range' => strtoupper($identifier),
                'suffixes' => $body,
                'client_match' => true,
            ],
        ];
    }
}
