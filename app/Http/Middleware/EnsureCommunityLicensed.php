<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Services\CommunityLicenseService;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Blocks NEW exposure checks when the Community license/trial has expired.
 * Everything else (history, reports, settings, license page) stays fully
 * usable - see README "Licensing".
 */
class EnsureCommunityLicensed
{
    public function __construct(private readonly CommunityLicenseService $license) {}

    public function handle(Request $request, Closure $next): Response
    {
        if ($this->license->checksAllowed()) {
            return $next($request);
        }

        $msg = 'Your Community Edition trial has ended. Activate a FREE license key to keep running checks '
            . '(takes 30 seconds at ' . $this->license->serverUrl() . '/community-license).';

        if ($request->expectsJson() || $request->is('api/*')) {
            return response()->json(['error' => $msg, 'license_required' => true], 402);
        }

        return redirect()
            ->route('license')
            ->with('error', $msg);
    }
}
