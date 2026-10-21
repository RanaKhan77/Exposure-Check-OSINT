<?php

declare(strict_types=1);

use App\Http\Controllers\AssetController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\CheckController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\ExportController;
use App\Http\Controllers\LicenseController;
use App\Http\Controllers\SettingsController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Exposure-Check-OSINT — single-admin Community Edition
|--------------------------------------------------------------------------
| Public: login + display-image proxy (cached favicons/avatars).
| Admin session: dashboard check page, history, reports, settings, license.
| New checks additionally pass the community-license gate (trial -> free key).
*/

Route::get('/login', [AuthController::class, 'showLogin'])->name('login');
Route::post('/login', [AuthController::class, 'login'])->middleware('throttle:10,1')->name('login.attempt');
Route::post('/logout', [AuthController::class, 'logout'])->name('logout');

// Display images for result cards (logo grid / avatars) — cache-first proxy.
Route::get('/osint-logo/{key}', [AssetController::class, 'logo'])
    ->middleware('throttle:120,1')->name('asset.logo');
Route::get('/osint-avatar/gravatar/{hash}', [AssetController::class, 'gravatar'])
    ->middleware('throttle:120,1')->name('asset.gravatar');

Route::middleware(['admin'])->group(function () {
    Route::get('/', [DashboardController::class, 'index'])->name('dashboard');
    Route::get('/history', [DashboardController::class, 'history'])->name('history');
    Route::get('/report/{check}', [DashboardController::class, 'report'])->name('report');

    // v1.1: download a stored check as JSON or CSV (same admin gate as
    // the report itself; identifiers stay masked, credentials stripped).
    Route::get('/report/{check}/export/{format}', [ExportController::class, 'export'])
        ->whereIn('format', ['json', 'csv'])->name('report.export');
    Route::delete('/history/{check}', [DashboardController::class, 'destroy'])->name('history.destroy');
    Route::post('/history/purge', [DashboardController::class, 'purge'])->name('history.purge');

    Route::get('/settings', [SettingsController::class, 'index'])->name('settings');
    Route::post('/settings', [SettingsController::class, 'save'])->name('settings.save');

    Route::get('/license', [LicenseController::class, 'index'])->name('license');
    Route::post('/license/activate', [LicenseController::class, 'activate'])->name('license.activate');
    Route::post('/license/deactivate', [LicenseController::class, 'deactivate'])->name('license.deactivate');

    // New checks: burst-limited, quota-counted, license-gated.
    Route::post('/api/check', [CheckController::class, 'check'])
        ->middleware(['licensed', 'throttle:30,1'])->name('api.check');
});
