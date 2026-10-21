<?php

use App\Services\CommunityLicenseService;
use Illuminate\Support\Facades\Schedule;

// Community license: weekly re-validation + daily install heartbeat
// (same honest cadence as the Website Vulnerability Scanner CE).
Schedule::call(fn () => app(CommunityLicenseService::class)->validate())->weekly();
Schedule::call(fn () => app(CommunityLicenseService::class)->heartbeat())->daily();
