<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Modules\Osint\OsintCheckService;
use App\Services\SettingsService;
use Illuminate\Http\Request;

class SettingsController extends Controller
{
    public function __construct(
        private readonly SettingsService $settings,
        private readonly OsintCheckService $osint,
    ) {
    }

    public function index()
    {
        $sourceRows = [];
        foreach (OsintCheckService::SOURCES as $cls) {
            $src = app($cls);
            $sourceRows[] = [
                'key' => $src->key(),
                'label' => $src->label(),
                'category' => $src->category(),
                'enabled' => (bool) $this->settings->get("sources.{$src->key()}.enabled", true),
            ];
        }

        return view('settings', [
            'title' => 'Settings — Exposure-Check-OSINT',
            'values' => [
                'daily_check_limit' => $this->settings->get('daily_check_limit', 200),
                'burst_per_minute' => $this->settings->get('burst_per_minute', 10),
                'cache_ttl_seconds' => $this->settings->get('cache_ttl_seconds', 1800),
                'user_agent' => $this->settings->get('user_agent', SettingsService::DEFAULTS['user_agent']),
            ],
            'sources' => $sourceRows,
        ]);
    }

    public function save(Request $request)
    {
        $data = $request->validate([
            'daily_check_limit' => ['required', 'integer', 'min:1', 'max:100000'],
            'burst_per_minute' => ['required', 'integer', 'min:2', 'max:120'],
            'cache_ttl_seconds' => ['required', 'integer', 'min:60', 'max:86400'],
            'user_agent' => ['required', 'string', 'max:300'],
            'sources' => ['nullable', 'array'],
        ]);

        $this->settings->set('daily_check_limit', (int) $data['daily_check_limit']);
        $this->settings->set('burst_per_minute', (int) $data['burst_per_minute']);
        $this->settings->set('cache_ttl_seconds', (int) $data['cache_ttl_seconds']);
        $this->settings->set('user_agent', trim((string) $data['user_agent']));

        // Source toggles: absent checkbox = disabled (plain HTML form semantics)
        $enabled = array_map('strval', (array) ($data['sources'] ?? []));
        foreach (OsintCheckService::SOURCES as $cls) {
            $src = app($cls);
            $this->settings->set("sources.{$src->key()}.enabled", in_array($src->key(), $enabled, true));
        }

        return redirect()->route('settings')->with('status', 'Settings saved.');
    }
}
