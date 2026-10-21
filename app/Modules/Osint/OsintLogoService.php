<?php

declare(strict_types=1);

namespace App\Modules\Osint;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Storage;

/**
 * OsintLogoService v1.0 — favicon/logo + avatar cache for Exposure Check v2.
 * =============================================================================
 * Purpose: give the OSINT result cards the "competitor look" — per-site logos
 * and profile photos (emailosint.org / behindtheemail.com style) — without
 * leaking the visitor's browser to third parties and without live third-party
 * dependencies on every render.
 *
 * Design:
 *   - Site logos:  favicon of the site's own domain, fetched ONCE by the
 *     server (5s budget), cached at storage osint-logos/{key}.{ext}; served
 *     by the /osint-logo/{key} route. Negative results cached 24h as
 *     {key}.miss so a dead favicon endpoint cannot hammer the origin.
 *   - Avatars:     gravatar.com/avatar/{md5}?d=404 fetched once, cached at
 *     osint-avatars/{md5}.png, served by /osint-avatar/gravatar/{md5}.
 *   - Registry:    osint-logos/registry.json maps logo key -> domain so the
 *     asset route knows which favicon to try on cache miss.
 *
 * ETHICS/LEGAL: favicons and public profile photos are public by definition.
 * We fetch them from OUR server (visitor IP never touches the origin), we
 * cache them (one fetch per site per day worst case), and the frontend shows
 * a letter-tile fallback whenever an asset is unavailable — we never block
 * results on images.
 */
class OsintLogoService
{
    private const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

    private const MISS_TTL = 86400; // retry a failed favicon after 24h

    /** @var array<string,string>|null */
    private ?array $registryCache = null;

    // ---------------------------------------------------------------- helpers

    /** Stable logo key for a human site name ("GitHub" -> "github"). */
    public static function keyForSite(string $siteName): string
    {
        $key = strtolower(trim($siteName));
        $key = preg_replace('/[^a-z0-9]+/', '_', $key) ?? '';
        $key = trim($key, '_');

        return $key !== '' ? substr($key, 0, 48) : 'site';
    }

    /** Registrable domain from a profile URL ("https://www.youtube.com/@x" -> "youtube.com"). */
    public static function domainFromUrl(string $url): ?string
    {
        $host = parse_url($url, PHP_URL_HOST);
        if (!is_string($host) || $host === '') {
            return null;
        }
        $host = preg_replace('/^www\./i', '', strtolower($host));

        return $host ?: null;
    }

    // ---------------------------------------------------------------- registry

    /** Remember that logo {key} should be fetched from {domain}. Idempotent. */
    public function registerSite(string $key, string $domain): void
    {
        $key = self::keyForSite($key);
        $domain = strtolower(trim($domain));
        if ($domain === '' || !filter_var($domain, FILTER_VALIDATE_DOMAIN)) {
            return;
        }
        $reg = $this->registry();
        if (($reg[$key] ?? null) === $domain) {
            return; // already registered — no write churn
        }
        $reg[$key] = $domain;
        try {
            Storage::disk('local')->put('osint-logos/registry.json', (string) json_encode($reg, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), ['visibility' => 'public']);
            @chmod(Storage::disk('local')->path('osint-logos/registry.json'), 0644);
            $this->registryCache = $reg;
        } catch (\Throwable $e) {
            // registry write failure only disables logo caching, never results
        }
    }

    /** @return array<string,string> */
    private function registry(): array
    {
        if ($this->registryCache !== null) {
            return $this->registryCache;
        }
        try {
            $raw = Storage::disk('local')->get('osint-logos/registry.json');
            $doc = is_string($raw) ? json_decode($raw, true) : null;
            $this->registryCache = is_array($doc) ? $doc : [];
        } catch (\Throwable $e) {
            $this->registryCache = [];
        }

        return $this->registryCache;
    }

    // ---------------------------------------------------------------- site logos

    /**
     * Serve-ready cached logo for {key}: ['path' => absolute, 'type' => mime].
     * Tries a live fetch (once per 24h) when not cached. Null = use letter tile.
     *
     * @return array{path: string, type: string}|null
     */
    public function siteLogo(string $key): ?array
    {
        $key = self::keyForSite($key);
        $cached = $this->cachedFile('osint-logos', $key);
        if ($cached !== null) {
            return $cached;
        }
        if ($this->missIsFresh('osint-logos', $key)) {
            return null; // recent failure — do not hammer the origin
        }
        $domain = $this->registry()[self::keyForSite($key)] ?? null;
        if ($domain === null || $domain === '') {
            return null;
        }
        foreach (['https://' . $domain . '/favicon.ico', 'https://www.' . $domain . '/favicon.ico', 'https://' . $domain . '/favicon.png'] as $url) {
            $bin = $this->fetchImage($url);
            if ($bin !== null) {
                $ext = self::extForMagic($bin['head']) ?? 'ico';
                $path = 'osint-logos/' . $key . '.' . $ext;
                try {
                    Storage::disk('local')->put($path, $bin['body'], ['visibility' => 'public']);
                    if (!Storage::disk('local')->exists($path) || Storage::disk('local')->size($path) < 64) {
                        throw new \RuntimeException('write not durable');
                    }
                    @chmod(Storage::disk('local')->path('osint-logos'), 0755);
                    @chmod(Storage::disk('local')->path($path), 0644);
                } catch (\Throwable $e) {
                    $this->writeMiss('osint-logos', $key);

                    return null; // never hand out a path that was not written
                }
                $this->clearMiss('osint-logos', $key);

                return ['path' => Storage::disk('local')->path($path), 'type' => self::mimeForExt($ext)];
            }
        }
        $this->writeMiss('osint-logos', $key);

        return null;
    }

    // ---------------------------------------------------------------- avatars

    /**
     * Gravatar avatar (public by definition) for an md5 email hash.
     *
     * @return array{path: string, type: string}|null
     */
    public function gravatarAvatar(string $md5): ?array
    {
        $md5 = strtolower(preg_replace('/[^a-f0-9]/', '', $md5) ?? '');
        if (strlen($md5) !== 32) {
            return null;
        }
        $cached = $this->cachedFile('osint-avatars', $md5);
        if ($cached !== null) {
            return $cached;
        }
        if ($this->missIsFresh('osint-avatars', $md5)) {
            return null;
        }
        $bin = $this->fetchImage('https://gravatar.com/avatar/' . $md5 . '?d=404&s=128');
        if ($bin !== null) {
            $ext = self::extForMagic($bin['head']) ?? 'png';
            $path = 'osint-avatars/' . $md5 . '.' . $ext;
            try {
                Storage::disk('local')->put($path, $bin['body'], ['visibility' => 'public']);
                if (!Storage::disk('local')->exists($path) || Storage::disk('local')->size($path) < 64) {
                    throw new \RuntimeException('write not durable');
                }
                @chmod(Storage::disk('local')->path('osint-avatars'), 0755);
                @chmod(Storage::disk('local')->path($path), 0644);
            } catch (\Throwable $e) {
                $this->writeMiss('osint-avatars', $md5);

                return null; // never hand out a path that was not written
            }
            $this->clearMiss('osint-avatars', $md5);

            return ['path' => Storage::disk('local')->path($path), 'type' => self::mimeForExt($ext)];
        }
        $this->writeMiss('osint-avatars', $md5);

        return null;
    }

    // ---------------------------------------------------------------- internals

    /** @return array{path: string, type: string}|null */
    private function cachedFile(string $dir, string $name): ?array
    {
        foreach (['png', 'ico', 'jpg', 'jpeg', 'gif', 'svg'] as $ext) {
            $rel = $dir . '/' . $name . '.' . $ext;
            try {
                if (Storage::disk('local')->exists($rel) && Storage::disk('local')->size($rel) > 0) {
                    return ['path' => Storage::disk('local')->path($rel), 'type' => self::mimeForExt($ext)];
                }
            } catch (\Throwable $e) {
                continue;
            }
        }

        return null;
    }

    private function missIsFresh(string $dir, string $name): bool
    {
        try {
            $rel = $dir . '/' . $name . '.miss';
            if (!Storage::disk('local')->exists($rel)) {
                return false;
            }
            $ts = (int) Storage::disk('local')->get($rel);

            return (time() - $ts) < self::MISS_TTL;
        } catch (\Throwable $e) {
            return false;
        }
    }

    private function writeMiss(string $dir, string $name): void
    {
        try {
            Storage::disk('local')->put($dir . '/' . $name . '.miss', (string) time(), ['visibility' => 'public']);
            @chmod(Storage::disk('local')->path($dir), 0755);
        } catch (\Throwable $e) {
            // negative-cache failure is non-fatal
        }
    }

    private function clearMiss(string $dir, string $name): void
    {
        try {
            if (Storage::disk('local')->exists($dir . '/' . $name . '.miss')) {
                Storage::disk('local')->delete($dir . '/' . $name . '.miss');
            }
        } catch (\Throwable $e) {
        }
    }

    /**
     * Fetch an image with a hard 5s budget; validate magic bytes + size.
     *
     * @return array{head: string, body: string}|null
     */
    private function fetchImage(string $url): ?array
    {
        try {
            $resp = Http::timeout(6)
                ->connectTimeout(4)
                ->withHeaders(['User-Agent' => self::UA, 'Accept' => 'image/*,*/*;q=0.8'])
                ->get($url);
        } catch (ConnectionException $e) {
            return null;
        } catch (\Throwable $e) {
            return null;
        }
        if (!$resp->ok()) {
            return null;
        }
        $body = (string) $resp->body();
        $len = strlen($body);
        if ($len < 64 || $len > 262144) {
            return null; // empty stub or oversized blob
        }
        $head = substr($body, 0, 16);
        if (self::extForMagic($head) === null) {
            return null; // not an image we can render
        }

        return ['head' => $head, 'body' => $body];
    }

    /** @return string|null ext for magic bytes */
    private static function extForMagic(string $head): ?string
    {
        if (strncmp($head, "\x89PNG", 4) === 0) { return 'png'; }
        if (strncmp($head, 'GIF8', 4) === 0) { return 'gif'; }
        if (strncmp($head, "\xFF\xD8", 2) === 0) { return 'jpg'; }
        if (strncmp($head, "\x00\x00\x01\x00", 4) === 0) { return 'ico'; }
        $t = ltrim($head);
        if (strncmp($t, '<svg', 4) === 0 || strncmp($t, '<?xml', 5) === 0) {
            // SVG refused: /osint-logo/* is a same-origin public route and a
            // crafted SVG executes script on this origin. Favicons are
            // png/ico/jpg/gif/webp in practice (security review 2026-10-21).
            return null;
        }

        return null;
    }

    private static function mimeForExt(string $ext): string
    {
        return match ($ext) {
            'png' => 'image/png',
            'gif' => 'image/gif',
            'jpg', 'jpeg' => 'image/jpeg',
            'svg' => 'image/svg+xml',
            default => 'image/x-icon',
        };
    }
}
