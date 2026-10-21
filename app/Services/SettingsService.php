<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\Setting;
use Illuminate\Support\Facades\Cache;

/**
 * Tiny settings layer for the single-admin CE dashboard: key => JSON value
 * rows, cached for a minute so the hot check path never hits the DB, with
 * sane defaults defined here (Settings page edits override them).
 */
class SettingsService
{
    public const DEFAULTS = [
        // own-use default: 200 checks/day, 10/min burst
        'daily_check_limit' => 200,
        'burst_per_minute' => 10,
        // result cache TTL (seconds)
        'cache_ttl_seconds' => 1800,
        // honest User-Agent sent to every OSINT source
        'user_agent' => 'Exposure-Check-OSINT/1.0 (+https://github.com/RanaKhan77/Exposure-Check-OSINT)',
        // per-source enable/disable: sources.<key>.enabled => bool
        // (absent = enabled; the Settings page writes explicit flags)
    ];

    public function get(string $key, mixed $default = null): mixed
    {
        $all = $this->all();
        if (array_key_exists($key, $all)) {
            return $all[$key];
        }

        return $default;
    }

    public function set(string $key, mixed $value): void
    {
        Setting::updateOrCreate(['key' => $key], ['value' => $value]);
        Cache::forget($this->cacheKey());
    }

    public function all(): array
    {
        /** @var array<string, mixed>|null $cached */
        $cached = Cache::get($this->cacheKey());
        if (is_array($cached)) {
            return $cached;
        }

        $out = self::DEFAULTS;
        try {
            foreach (Setting::query()->get(['key', 'value']) as $row) {
                $out[$row->key] = $row->value;
            }
        } catch (\Throwable $e) {
            // settings table not migrated yet / sqlite missing - defaults win
        }

        Cache::put($this->cacheKey(), $out, 60);

        return $out;
    }

    public function flush(): void
    {
        Cache::forget($this->cacheKey());
    }

    private function cacheKey(): string
    {
        return 'ec.settings.v1';
    }
}
