<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\ExposureCheck;
use App\Modules\Osint\OsintCheckService;
use App\Services\SettingsService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;

/**
 * POST /api/check — run one exposure check.
 *
 * Single-admin CE: quota is per-install per-day (own-use product), burst
 * limited per IP to protect the third-party sources. Password checks carry
 * ONLY the 5-char SHA-1 prefix (k-anonymity; hashed in the browser).
 */
class CheckController extends Controller
{
    public function __construct(
        private readonly OsintCheckService $osint,
        private readonly SettingsService $settings,
    ) {
    }

    public function check(Request $request): JsonResponse
    {
        $type = strtolower((string) $request->input('type', ''));
        $identifier = trim((string) $request->input('q', ''));

        if ($type === 'password') {
            // k-anonymity: the browser sends ONLY the 5-hex SHA-1 prefix -
            // never the full hash, never the password. (Contract aligned with
            // the UI text and PwnedPasswordsSource; see docs/PRIVACY.md.)
            $prefix = strtoupper(trim((string) $request->input('prefix', '')));
            if (!preg_match('/^[0-9A-F]{5}$/', $prefix)) {
                return response()->json(['ok' => false, 'error' => 'Invalid password prefix — must be exactly 5 hexadecimal characters.'], 422);
            }
            $identifier = $prefix;
        }

        if (!in_array($type, OsintCheckService::TYPES, true)) {
            return response()->json(['ok' => false, 'error' => 'Unsupported check type.'], 422);
        }

        // Burst limit per IP protects upstream sources.
        $burst = max(2, (int) $this->settings->get('burst_per_minute', 10));
        $burstKey = 'ec-burst:' . $request->ip();
        if (!RateLimiter::tooManyAttempts($burstKey, $burst)) {
            RateLimiter::hit($burstKey, 60);
        } else {
            return response()->json(['ok' => false, 'error' => 'Too many requests — please wait a minute.'], 429);
        }

        $quota = $this->quota();
        if ($quota['remaining'] <= 0) {
            return response()->json([
                'ok' => false,
                'error' => 'Daily limit reached (' . $quota['limit'] . '/day, resets at midnight). Adjust it on the Settings page.',
                'quota' => $quota,
            ], 429);
        }

        try {
            $result = $this->osint->run($type, $identifier);
        } catch (\InvalidArgumentException $e) {
            return response()->json(['ok' => false, 'error' => $e->getMessage()], 422);
        } catch (\Throwable $e) {
            \Illuminate\Support\Facades\Log::warning('exposure check failed: ' . $e->getMessage());

            return response()->json(['ok' => false, 'error' => 'Check failed — please retry in a moment.'], 502);
        }

        // Persist audit row (hashed identifier + masked display only;
        // credential material stripped before storage).
        $checkId = null;
        try {
            $stored = $this->osint->sanitizeForStorage($result);
            $row = ExposureCheck::create([
                'type' => $type,
                'identifier_hash' => $this->osint->identifierHash($type, $identifier),
                'identifier_masked' => $result['identifier_masked'],
                'total_sources' => $result['summary']['sources_assessed'],
                'hits' => $result['summary']['hits'],
                'exposure_score' => $result['summary']['exposure_score'],
                'results' => $type === 'password' ? null : $stored['sources'],
            ]);
            $checkId = $row->id;
        } catch (\Throwable $e) {
            \Illuminate\Support\Facades\Log::warning('exposure audit row failed: ' . $e->getMessage());
        }

        $quota = $this->quota();
        $result['quota'] = $quota;
        $result['check_id'] = $checkId;

        return response()->json(['ok' => true, 'check' => $result, 'quota' => $quota]);
    }

    /** Per-install daily quota (own-use product — Settings page adjusts it). */
    private function quota(): array
    {
        $limit = max(1, (int) $this->settings->get('daily_check_limit', 200));
        $used = ExposureCheck::query()
            ->where('created_at', '>=', now()->startOfDay())
            ->count();

        return ['used' => $used, 'limit' => $limit, 'remaining' => max(0, $limit - $used)];
    }
}
