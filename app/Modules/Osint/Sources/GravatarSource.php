<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use App\Modules\Osint\OsintLogoService;
use Illuminate\Http\Client\Response;

/**
 * Gravatar public profile lookup v2 — keyless email footprint signal.
 * =============================================================================
 * Two public probes:
 *   1. Classic avatar endpoint  https://gravatar.com/avatar/{md5}?d=404&s=64
 *      200 = public profile exists; 404 = none.
 *   2. Public profile document   https://gravatar.com/{md5}.json
 *      -> preferredUsername, about, currentLocation, profileUrl, links,
 *         accounts (all public by Gravatar definition).
 *
 * DISPLAY v2 (Exposure Check card): the card now shows the actual avatar
 * photo (proxied through /osint-avatar/gravatar/{md5} so the visitor's
 * browser never talks to gravatar.com) plus the public profile fields
 * (display name, about, location) — emailosint.org / behindtheemail.com
 * parity.
 *
 * ETHICS: we report only data Gravatar itself publishes publicly. The avatar
 * is fetched by OUR server once and cached 24h; a missing avatar degrades to
 * the letter-tile fallback, never blocks the card.
 */
class GravatarSource implements OsintSource
{
    public function key(): string
    {
        return 'gravatar';
    }

    public function label(): string
    {
        return 'Gravatar — Public Profile & Photo';
    }

    public function category(): string
    {
        return 'profile';
    }

    public function supports(string $type): bool
    {
        return $type === 'email';
    }

    public function requests(string $type, string $identifier): array
    {
        $hash = md5(strtolower(trim($identifier)));

        return [
            [
                'name' => $this->key() . '.main',
                'method' => 'GET',
                'url' => 'https://gravatar.com/avatar/' . $hash . '?d=404&s=64',
            ],
            [
                'name' => $this->key() . '.profile',
                'method' => 'GET',
                'url' => 'https://gravatar.com/' . $hash . '.json',
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $resp = $responses[$this->key() . '.main'] ?? null;
        $prof = $responses[$this->key() . '.profile'] ?? null;
        if (!$resp instanceof Response) {
            return ['status' => 'unavailable', 'summary' => 'Gravatar footprint check unavailable right now.', 'data' => []];
        }

        $exists = $resp->ok();
        $profile = null;
        if ($prof instanceof Response && $prof->ok()) {
            try {
                $doc = $prof->json();
                $entry = is_array($doc) && isset($doc['entry'][0]) && is_array($doc['entry'][0])
                    ? $doc['entry'][0]
                    : null;
                if ($entry !== null) {
                    $profile = $entry;
                }
            } catch (\Throwable $e) {
                $profile = null; // profile doc failure degrades to avatar-only
            }
        }

        if (!$exists && $resp->status() !== 404) {
            return ['status' => 'unavailable', 'summary' => 'Gravatar footprint check unavailable right now.', 'data' => []];
        }

        if (!$exists) {
            return [
                'status' => 'clean',
                'summary' => 'No public Gravatar profile is attached to this email address.',
                'severity' => 'info',
                'data' => ['profile_exists' => false],
            ];
        }

        $hash = md5(strtolower(trim($identifier)));
        $data = [
            'profile_exists' => true,
            'image_url' => '/osint-avatar/gravatar/' . $hash,
        ];

        if (is_array($profile)) {
            $name = trim((string) ($profile['preferredUsername'] ?? ''));
            $about = trim((string) ($profile['about'] ?? ''));
            $loc = trim((string) ($profile['currentLocation'] ?? ''));
            $purl = trim((string) ($profile['profileUrl'] ?? ''));
            $links = isset($profile['links']) && is_array($profile['links']) ? $profile['links'] : [];
            $accs = isset($profile['accounts']) && is_array($profile['accounts']) ? $profile['accounts'] : [];

            if ($name !== '') { $data['display_name'] = $name; }
            if ($about !== '') { $data['about'] = mb_substr($about, 0, 280); }
            if ($loc !== '') { $data['location'] = $loc; }
            if (filter_var($purl, FILTER_VALIDATE_URL)) { $data['profile_url'] = $purl; }
            if ($links !== []) { $data['public_links'] = count($links); }
            if ($accs !== []) { $data['linked_services'] = count($accs); }
        }

        $hasProfileDoc = is_array($profile);
        return [
            'status' => 'hit',
            'summary' => 'A public Gravatar profile exists for this email — the public photo, display name'
                . ($hasProfileDoc ? ', location and public links' : '')
                . ' are visible to anyone. Shown below as they appear publicly.',
            'severity' => 'low',
            'data' => $data,
        ];
    }
}
