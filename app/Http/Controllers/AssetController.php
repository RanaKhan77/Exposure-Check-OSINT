<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Modules\Osint\OsintLogoService;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\BinaryFileResponse;

/**
 * Serves cached OSINT display images (the graphical result cards).
 * /osint-logo/{key}              -> platform favicon (logo grid on cards)
 * /osint-avatar/gravatar/{md5}   -> profile avatar (Gravatar card)
 *
 * Cache-first; on miss the service tries ONE live fetch (5s budget, 24h
 * negative cache). 404 otherwise - the frontend letter-tile fallback takes
 * over, so a missing image never blocks or degrades results.
 */
class AssetController extends Controller
{
    public function logo(Request $request, string $key): BinaryFileResponse|\Illuminate\Http\JsonResponse
    {
        // Prevent path traversal in key parameter
        if (preg_match('#\.\.[\\\/]#', $key)) {
            abort(400, 'Invalid key parameter');
        }
        $key = OsintLogoService::keyForSite($key);
        $asset = app(OsintLogoService::class)->siteLogo($key);
        if ($asset === null) {
            return response()->json(['ok' => false], 404);
        }

        return response()->file($asset['path'], [
            'Content-Type' => $asset['type'],
            'Cache-Control' => 'public, max-age=86400',
        ]);
    }

    public function gravatar(Request $request, string $hash): BinaryFileResponse|\Illuminate\Http\JsonResponse
    {
        if (!preg_match('/^[0-9a-f]{32}$/i', $hash)) {
            abort(400, 'Invalid hash');
        }
        $asset = app(OsintLogoService::class)->gravatarAvatar(strtolower($hash));
        if ($asset === null) {
            return response()->json(['ok' => false], 404);
        }

        return response()->file($asset['path'], [
            'Content-Type' => $asset['type'],
            'Cache-Control' => 'public, max-age=86400',
        ]);
    }
}
