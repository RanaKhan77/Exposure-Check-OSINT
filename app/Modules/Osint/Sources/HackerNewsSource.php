<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * Hacker News (Firebase public API) - keyless account-existence check.
 * GET https://hacker-news.firebaseio.com/v0/user/{username}.json
 *   -> {"created":epoch,"id":"pg","karma":N,"submitted":[ids...]}
 *   -> JSON null (or 404) for a user that does not exist.
 *
 * Adds a distinct long-lived discussion platform to the linked-account
 * footprint (karma + join year double as activity/age signals). R6-B
 * live-verified 2026-10-20 (keyless, JSON).
 */
class HackerNewsSource implements OsintSource
{
    private const URL = 'https://hacker-news.firebaseio.com/v0/user/';

    public function key(): string
    {
        return 'hackernews';
    }

    public function label(): string
    {
        return 'Hacker News — Account Existence';
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
        if ($user === '' || strlen($user) > 30 || !preg_match('/^[a-z0-9_-]+$/', $user)) {
            return [];
        }

        return [
            [
                'name' => $this->key() . '.main',
                'method' => 'GET',
                'url' => self::URL . urlencode($user) . '.json',
                'headers' => ['Accept' => 'application/json'],
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $resp = $responses[$this->key() . '.main'] ?? null;
        if (!$resp instanceof Response) {
            return ['status' => 'unavailable', 'summary' => 'Hacker News lookup unavailable right now.', 'data' => []];
        }

        // Firebase returns 200 with a JSON null body for missing users and
        // 404 on transport oddities; only 5xx counts as unavailable.
        if ($resp->status() >= 500) {
            return ['status' => 'unavailable', 'summary' => 'Hacker News lookup unavailable right now.', 'data' => []];
        }

        $j = $resp->json();
        if (!is_array($j) || empty($j['id'])) {
            return [
                'status' => 'clean',
                'severity' => 'info',
                'summary' => 'No Hacker News account found for this username.',
                'data' => ['exists' => false],
            ];
        }

        $created = isset($j['created']) ? (int) $j['created'] : 0;
        $year = $created > 0 ? (string) gmdate('Y', $created) : '';
        $submitted = is_array($j['submitted'] ?? null) ? count($j['submitted']) : 0;

        $data = [
            'exists' => true,
            'id' => (string) $j['id'],
            'karma' => (int) ($j['karma'] ?? 0),
            'member_since' => $year,
            'activity_items' => $submitted,
        ];

        return [
            'status' => 'hit',
            'severity' => 'low',
            'summary' => sprintf(
                'Hacker News account exists (%s%s%s) — public discussion footprint.',
                $data['id'],
                $data['karma'] > 0 ? sprintf(', %s karma', number_format($data['karma'])) : '',
                $year !== '' ? ', member since ' . $year : ''
            ),
            'data' => $data,
        ];
    }
}
