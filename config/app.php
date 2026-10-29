<?php

return [
    'name' => env('APP_NAME', 'Exposure-Check-OSINT'),
    'version' => '1.5.0',
    'env' => env('APP_ENV', 'production'),
    'debug' => (bool) env('APP_DEBUG', false),
    'url' => env('APP_URL', 'http://localhost'),
    'timezone' => env('APP_TIMEZONE', 'UTC'),
    'locale' => env('APP_LOCALE', 'en'),
    'fallback_locale' => 'en',
    'faker_locale' => 'en_US',
    'cipher' => 'AES-256-CBC',
    'key' => env('APP_KEY'),
    'previous_keys' => [...array_filter(explode(',', (string) env('APP_PREVIOUS_KEYS', '')))],
    // Single-admin sign-in (install.sh / container entrypoint generates it).
    // Lives in config (not runtime env()) so it survives `config:cache`.
    'admin_password' => env('ADMIN_PASSWORD', ''),

    'maintenance' => [
        'driver' => env('APP_MAINTENANCE_DRIVER', 'file'),
        'store' => env('APP_MAINTENANCE_STORE', 'database'),
    ],
];
