<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\CommunityLicense;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * Community Edition license client (Exposure-Check-OSINT product identity).
 *
 * Same honest pattern as the Website Vulnerability Scanner CE:
 *  - First boot starts a 14-day full-feature trial (LICENSE_TRIAL_DAYS).
 *  - After the trial, NEW checks are blocked until a free key from
 *    https://2mny.com/community-license is activated. Existing history and
 *    every other admin page keep working.
 *  - Activation + weekly re-validation + daily heartbeat talk to
 *    LICENSE_SERVER_URL over HTTPS. If the license server is unreachable
 *    the install keeps working for a 7-day grace window (offline-friendly).
 *  - This is open source: the check is intentionally easy to audit and
 *    easy to remove. It exists for install tracking and free premium
 *    update notifications - not as DRM.
 *
 * Product identity: every call carries product=exposure-check so install
 * telemetry stays separate from the scanner CE on the license server.
 */
class CommunityLicenseService
{
    public const PRODUCT = 'exposure-check';
    public const GRACE_DAYS = 7;

    public function serverUrl(): string
    {
        return rtrim((string) config('license.server_url', env('LICENSE_SERVER_URL', 'https://2mny.com')), '/');
    }

    public function trialDays(): int
    {
        return max(1, (int) (config('license.trial_days', 14) ?: 14));
    }

    /**
     * The single license row; creates the trial on first call.
     */
    public function state(): CommunityLicense
    {
        $row = CommunityLicense::query()->orderByDesc('id')->first();
        if ($row === null) {
            $row = CommunityLicense::create([
                'status' => 'trial',
                'install_id' => $this->installId(),
                'product' => self::PRODUCT,
                'trial_started_at' => now(),
                'trial_ends_at' => now()->addDays($this->trialDays()),
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
     * Effective license status for gating.
     *      licensed  -> checks allowed
     *      trial     -> checks allowed while trial_ends_at is in the future
     *      grace     -> licensed but the server was unreachable > 7 days
     *      blocked   -> trial expired (or revoked / grace expired)
     */
    public function status(): string
    {
        $row = $this->state();

        if ($row->status === 'revoked') {
            return 'blocked';
        }

        if ($row->status === 'licensed') {
            $expires = $row->expiresAt();
            if ($expires !== null && $expires->isPast()) {
                return 'blocked';
            }
            if ($row->last_validated_at
                && $row->last_validated_at->copy()->addDays(self::GRACE_DAYS)->isPast()) {
                return 'grace';
            }
            return 'licensed';
        }

        // trial
        if ($row->trial_ends_at && $row->trial_ends_at->isFuture()) {
            return 'trial';
        }
        return 'blocked';
    }

    public function checksAllowed(): bool
    {
        return in_array($this->status(), ['trial', 'licensed', 'grace'], true);
    }

    /**
     * Activate a free license key against the license server.
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
     * Weekly re-validation (scheduled). Stores the server answer; network
     * failures never lock a licensed install inside the grace window.
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
                    $row->update(['status' => 'revoked', 'response_payload' => $data]);
                    return 'revoked';
                }
            }
        } catch (\Throwable $e) {
            Log::info('license validate unreachable: ' . $e->getMessage());
        }
        // unreachable or ambiguous: only refresh timestamp if still in grace
        if (!$row->last_validated_at
            || $row->last_validated_at->copy()->addDays(self::GRACE_DAYS)->isFuture()) {
            return 'unreachable-in-grace';
        }
        return 'unreachable-grace-expired';
    }

    /**
     * Daily heartbeat (scheduled): powers the project's install map and
     * free premium update notifications. Pure fire-and-forget.
     */
    public function heartbeat(): string
    {
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
