<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * Bluesky (AT Protocol public API) - keyless account-existence check.
 * GET https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={user}.bsky.social
 *   -> 200 {"did":"did:plc:...","handle":"...","displayName":"...",
 *           "followersCount":N,"followsCount":N,"postsCount":N,
 *           "createdAt":"2023-04-12T13:58:01.000Z"}
 *   -> 400/404 for a handle that does not exist.
 *
 * Bluesky is not covered by the maigret site database, so this adds a
 * distinct platform to the linked-account footprint. R6-B live-verified
 * 2026-10-20 (keyless, JSON).
 */
class BlueskySource implements OsintSource
{
    private const URL = 'https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=';

    public function key(): string
    {
        return 'bluesky';
    }

    public function label(): string
    {
        return 'Bluesky — Account Existence';
    }

    public function category(): string
    {
        return 'profile';
    }

    public function supports(string $type): bool
    {
        return $type === 'username';
    }

    public function requests(string $type, string $identifier): array
    {
        $user = strtolower(trim($identifier));
        if ($user === '' || strlen($user) > 60 || !preg_match('/^[a-z0-9._-]+$/', $user)) {
            return [];
        }

        $handle = str_contains($user, '.') ? $user : $user . '.bsky.social';

        return [
            [
                'name' => $this->key() . '.main',
                'method' => 'GET',
                'url' => self::URL . urlencode($handle),
                'headers' => ['Accept' => 'application/json'],
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $resp = $responses[$this->key() . '.main'] ?? null;
        if (!$resp instanceof Response) {
            return ['status' => 'unavailable', 'summary' => 'Bluesky lookup unavailable right now.', 'data' => []];
        }

        // Bluesky answers 400 (InvalidHandle/CouldNotFindRepo) for missing
        // accounts and 200 with the profile for existing ones. Transport
        // errors (5xx / connection) are the only true unavailability.
        if ($resp->status() >= 500) {
            return ['status' => 'unavailable', 'summary' => 'Bluesky lookup unavailable right now.', 'data' => []];
        }

        if ($resp->status() !== 200) {
            return [
                'status' => 'clean',
                'severity' => 'info',
                'summary' => 'No Bluesky account found under ' . strtolower(trim($identifier)) . '.bsky.social.',
                'data' => ['exists' => false],
            ];
        }

        $j = $resp->json();
        if (!is_array($j) || empty($j['did'])) {
            return [
                'status' => 'clean',
                'severity' => 'info',
                'summary' => 'No Bluesky account found under ' . strtolower(trim($identifier)) . '.bsky.social.',
                'data' => ['exists' => false],
            ];
        }

        $created = isset($j['createdAt']) && is_string($j['createdAt']) ? substr($j['createdAt'], 0, 10) : '';
        $data = [
            'exists' => true,
            'did' => (string) $j['did'],
            'handle' => isset($j['handle']) ? (string) $j['handle'] : '',
            'display_name' => isset($j['displayName']) ? (string) $j['displayName'] : '',
            'followers' => (int) ($j['followersCount'] ?? 0),
            'follows' => (int) ($j['followsCount'] ?? 0),
            'posts' => (int) ($j['postsCount'] ?? 0),
            'created' => $created,
        ];

        return [
            'status' => 'hit',
            'severity' => 'low',
            'summary' => sprintf(
                'Bluesky account exists (@%s%s%s) — public profile footprint.',
                $data['handle'],
                $data['followers'] > 0 ? sprintf(', %s followers', number_format($data['followers'])) : '',
                $created !== '' ? ', created ' . $created : ''
            ),
            'data' => $data,
        ];
    }
}
