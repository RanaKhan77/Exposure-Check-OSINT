<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Services\CommunityLicenseService;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * v2 "NO WALL" (2026-10-29): this middleware NEVER blocks anything.
 *
 * History: v1 blocked new exposure checks after a 14-day trial unless a
 * free key was activated. The same owner directive that removed the wall
 * from the Website Vulnerability Scanner CE applies here: the Community
 * Edition is fully functional forever, key or no key. The class is kept
 * (routes still reference it) but its only job now is a once-per-session,
 * non-blocking reminder that a FREE optional key exists (it powers update
 * notifications — nothing else).
 */
class EnsureCommunityLicensed
{
    public function __construct(private readonly CommunityLicenseService $license) {}

    public function handle(Request $request, Closure $next): Response
    {
        // Never gate. Just a gentle, once-per-session hint.
        if (!$request->session()->get('license_notice_shown')) {
            $status = $this->license->status();
            if ($status === 'unlicensed') {
                $request->session()->flash(
                    'info',
                    'Optional: activate a FREE license key to receive update notifications. '
                    . 'Checks work fully without one — no trial, no countdown, no phone-home. '
                    . 'Get a key at ' . $this->license->serverUrl() . '/community-license'
                );
            } elseif ($status === 'key-revoked') {
                $request->session()->flash(
                    'info',
                    'Your license key was revoked — checks keep working normally. '
                    . 'Only update notifications stopped; get a fresh free key at '
                    . $this->license->serverUrl() . '/community-license if you want them back.'
                );
            }
            $request->session()->put('license_notice_shown', true);
        }

        return $next($request);
    }
}
