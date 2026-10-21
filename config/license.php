<?php

declare(strict_types=1);

return [
    // Community Edition licensing — free keys from the project site.
    'server_url' => env('LICENSE_SERVER_URL', 'https://2mny.com'),
    'trial_days' => (int) (env('LICENSE_TRIAL_DAYS', 14) ?: 14),
    // Optional per-install override (the storage-file fallback generates one
    // automatically on first boot; .env wins when present).
    'install_id' => env('LICENSE_INSTALL_ID', ''),
];
