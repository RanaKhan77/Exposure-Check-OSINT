<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\CommunityLicense;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * Community Edition license client — v2 "NO WALL" (2026-10-29).
 *
 * Same owner directive as the Website Vulnerability Scanner CE v2: the
 * Community Edition must never block anyone. The license key is 100%
 * OPTIONAL tracking/notification convenience:
 *
 *  - Checks (and every other feature) are fully functional forever with
 *    NO key, NO trial countdown, NO phone-home. There is no "blocked"
 *    state anymore — status() returns 'licensed' or 'unlicensed' (plus
 *    'key-revoked'), purely informational (drives a gentle "add a free
 *    key for update notifications" hint).
 *  - Telemetry is OFF by default: the daily heartbeat and weekly
 *    re-validation schedules were REMOVED from routes/console.php. The
 *    only network calls happen when you explicitly activate, refresh or
 *    deactivate a key from the license page (LICENSE_SERVER_URL over
 *    HTTPS; payload: key, random install id, domain, version).
 *  - A key that the server marks revoked only means "this key no longer
 *    receives update notifications" — checks keep working. Get a new
 *    free key if you want the notifications back.
 *  - Fully offline-friendly: no network call is ever required to run
 *    checks, and network failures never change any functionality.
 *  - This is open source (Apache-2.0): the whole client is auditable and
 *    removable — it exists for voluntary install tracking and free
 *    update notifications, not as DRM.
 *
 * Product identity: every call carries product=exposure-check so install
 * telemetry stays separate from the scanner CE on the license server.
 */
class CommunityLicenseService
{
    public const PRODUCT = 'exposure-check';

    public function serverUrl(): string
    {
        return rtrim((string) config('license.server_url', env('LICENSE_SERVER_URL', 'https://2mny.com')), '/');
    }

    /**
     * The single license row; creates the (non-expiring) record on first call.
     */
    public function state(): CommunityLicense
    {
        $row = CommunityLicense::query()->orderByDesc('id')->first();
        if ($row === null) {
            $row = CommunityLicense::create([
                'status' => 'unlicensed',
                'install_id' => $this->installId(),
                'product' => self::PRODUCT,
                'trial_started_at' => now(), // kept for schema compatibility (install date)
            ]);
        }
        return $row;
    }

    /**
     * Stable per-install identifier (random, stored in a storage file,
     * generated here if missing) - never a hardware probe.
     */
    public function installId(): string
    {
        $id = (string) config('license.install_id', env('LICENSE_INSTALL_ID', ''));
        if ($id === '' || $id === null) {
            $lines = @file($this->installIdFile(), FILE_IGNORE_NEW_LINES) ?: [];
            foreach ($lines as $ln) {
                if (str_starts_with($ln, 'LICENSE_INSTALL_ID=')) {
                    $id = substr($ln, strlen('LICENSE_INSTALL_ID='));
                    break;
                }
            }
        }
        if ($id === '' || $id === null) {
            $id = 'EC-' . strtoupper(substr(bin2hex(random_bytes(10)), 0, 20));
            $this->persistInstallId('LICENSE_INSTALL_ID', $id);
        }
        return $id;
    }

    private function installIdFile(): string
    {
        return storage_path('app/license-install-id');
    }

    /**
     * Informational status for the optional-key hint. v2: there is NO
     * blocked state — this only drives UI hints, never gating.
     *      licensed     -> a key is activated (update notifications on)
     *      unlicensed   -> no key (everything still works; the license page
     *                      may suggest getting a free key for notifications)
     *      key-revoked  -> the activated key was revoked server-side; checks
     *                      keep working, only notifications stop
     */
    public function status(): string
    {
        $row = $this->state();

        if ($row->status === 'revoked') {
            return 'key-revoked';
        }

        if ($row->status === 'licensed' && $row->license_key) {
            return 'licensed';
        }

        return 'unlicensed';
    }

    /**
     * v2: ALWAYS true. Checks are never gated — see the class docblock.
     * (Method kept so older forks/blade guards keep working; it is
     * intentionally constant now.)
     */
    public function checksAllowed(): bool
    {
        return true;
    }

    /**
     * Activate a free license key against the license server (voluntary —
     * powers update notifications and the project's install counter).
     * Key format for this product: 2MNY-EC-XXXX-XXXX-XXXX-XXXX.
     */
    public function activate(string $key, ?string $domain = null): array
    {
        $key = strtoupper(trim($key));
        if (!preg_match('/^2MNY-EC-[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$/', $key)) {
            return ['ok' => false, 'message' => 'That does not look like an Exposure-Check-OSINT Community key (format 2MNY-EC-XXXX-XXXX-XXXX-XXXX). Get a free one at ' . $this->serverUrl() . '/community-license'];
        }

        $domain = $domain ?: ($_SERVER['SERVER_NAME'] ?? parse_url(config('app.url'), PHP_URL_HOST) ?? '');
        $domain = strtolower(preg_replace('/^www\./', '', (string) $domain));

        try {
            $resp = Http::asJson()->timeout(15)->post($this->serverUrl() . '/api/community-license/activate', [
                'product' => self::PRODUCT,
                'license_key' => $key,
                'domain' => $domain,
                'install_id' => $this->installId(),
                'version' => config('app.version', '1.0.0'),
            ]);
        } catch (\Throwable $e) {
            return ['ok' => false, 'message' => 'Could not reach the license server (' . $e->getMessage() . '). Please retry in a moment.'];
        }

        if ($resp->status() === 404 || $resp->status() === 422) {
            return ['ok' => false, 'message' => 'This key was not found or is not valid for this product. Double-check the key or request a new one at ' . $this->serverUrl() . '/community-license'];
        }
        if (!$resp->ok()) {
            return ['ok' => false, 'message' => 'License server responded with HTTP ' . $resp->status() . '. Please retry in a moment.'];
        }

        $data = (array) $resp->json();
        if (($data['status'] ?? '') !== 'active') {
            $msg = $data['message'] ?? 'This key is not active.';
            return ['ok' => false, 'message' => $msg . ' Request a fresh free key at ' . $this->serverUrl() . '/community-license'];
        }

        $row = $this->state();
        $row->update([
            'license_key' => $key,
            'status' => 'licensed',
            'domain' => $domain,
            'activated_at' => now(),
            'last_validated_at' => now(),
            'response_payload' => $data,
        ]);
        return ['ok' => true, 'message' => 'License activated. Thank you for supporting the project!'];
    }

    public function deactivate(): void
    {
        $row = $this->state();
        if ($row->license_key) {
            try {
                Http::asJson()->timeout(10)->post($this->serverUrl() . '/api/community-license/deactivate', [
                    'product' => self::PRODUCT,
                    'license_key' => $row->license_key,
                    'install_id' => $this->installId(),
                ]);
            } catch (\Throwable $e) {
                // best-effort
            }
        }
        $row->update(['status' => 'inactive', 'license_key' => null, 'response_payload' => null]);
    }

    /**
     * Manual re-validation (button on the license page — NOT scheduled
     * anymore; v2 removed the weekly cron). Only talks to the server when
     * a key is present; any failure leaves functionality untouched.
     */
    public function validate(): string
    {
        $row = $this->state();
        if ($row->status !== 'licensed' || !$row->license_key) {
            return 'skip-not-licensed';
        }
        try {
            $resp = Http::asJson()->timeout(15)->post($this->serverUrl() . '/api/community-license/validate', [
                'product' => self::PRODUCT,
                'license_key' => $row->license_key,
                'install_id' => $this->installId(),
                'domain' => $row->domain,
            ]);
            if ($resp->ok()) {
                $data = (array) $resp->json();
                if (($data['status'] ?? '') === 'active') {
                    $row->update(['last_validated_at' => now(), 'response_payload' => $data]);
                    return 'ok';
                }
                if (($data['status'] ?? '') === 'revoked') {
                    // v2: revocation only stops notifications — never checks.
                    $row->update(['status' => 'revoked', 'response_payload' => $data]);
                    return 'revoked';
                }
            }
        } catch (\Throwable $e) {
            Log::info('license validate unreachable: ' . $e->getMessage());
        }
        return 'unreachable';
    }

    /**
     * v2: heartbeat is DISABLED BY DEFAULT and no longer scheduled. Kept
     * only for operators who explicitly opt in with LICENSE_HEARTBEAT=on
     * (self-hosters who want to appear on the project's public install
     * map). The default install makes ZERO unsolicited network calls.
     */
    public function heartbeat(): string
    {
        if (strtolower((string) env('LICENSE_HEARTBEAT', 'off')) !== 'on') {
            return 'disabled';
        }
        $row = $this->state();
        try {
            Http::asJson()->timeout(10)->post($this->serverUrl() . '/api/community-license/heartbeat', [
                'product' => self::PRODUCT,
                'license_key' => $row->license_key,
                'install_id' => $row->install_id ?? $this->installId(),
                'status' => $this->status(),
                'domain' => $row->domain,
                'version' => config('app.version', '1.0.0'),
                'php' => PHP_VERSION,
            ]);
            return 'ok';
        } catch (\Throwable $e) {
            return 'unreachable';
        }
    }

    /**
     * Persist the install identity to a www-data-writable storage file.
     * (An .env value still wins when present.)
     */
    private function persistInstallId(string $key, string $value): void
    {
        try {
            $path = $this->installIdFile();
            $lines = file($path, FILE_IGNORE_NEW_LINES) ?: [];
            $found = false;
            foreach ($lines as $i => $ln) {
                if (str_starts_with($ln, $key . '=')) {
                    $lines[$i] = $key . '=' . $value;
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                $lines[] = $key . '=' . $value;
            }
            file_put_contents($path, implode("\n", $lines) . "\n");
        } catch (\Throwable $e) {
            // Never let identity persistence break a request.
            Log::warning('community-license: install-id persistence failed', ['e' => $e->getMessage()]);
        }
    }
}
