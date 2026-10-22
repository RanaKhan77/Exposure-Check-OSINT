<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Modules\Osint\OsintCheckService;
use App\Models\ExposureCheck;
use Illuminate\Http\Request;
use Illuminate\View\View;

class DashboardController extends Controller
{
    public function __construct(private readonly OsintCheckService $osint)
    {
    }

    /** GET / — the check page (single input, auto type detection). */
    public function index(Request $request): View
    {
        return view('dashboard', [
            'title' => 'Exposure Check — is your email, username, phone or password leaked?',
            'stats' => $this->osint->landingStats(),
            'sources' => $this->sourceDirectory(),
            'initialType' => $this->detectType((string) $request->query('q', '')),
            'initialQuery' => (string) $request->query('q', ''),
        ]);
    }

    /** GET /history — past checks (local only). */
    public function history(Request $request): View
    {
        $query = ExposureCheck::query()->orderByDesc('id');
        if ($request->filled('type')) {
            $query->where('type', (string) $request->input('type'));
        }

        return view('history', [
            'title' => 'History — Exposure-Check-OSINT',
            'checks' => $query->paginate(25)->withQueryString(),
        ]);
    }

    /** GET /report/{check} — clean printable HTML (browser print -> PDF). */
    public function report(Request $request, ExposureCheck $check)
    {
        return view('report', [
            'title' => 'Exposure Report — ' . $check->identifier_masked,
            'check' => $check,
        ]);
    }

    /** DELETE /history/{check} — privacy: delete one stored check. */
    public function destroy(Request $request, ExposureCheck $check)
    {
        $check->delete();

        return redirect()->route('history')->with('status', 'Check deleted.');
    }

    /** POST /history/purge — privacy: delete everything. */
    public function purge(Request $request)
    {
        $count = ExposureCheck::query()->count();
        ExposureCheck::query()->truncate();

        return redirect()->route('history')->with('status', $count . ' stored check(s) deleted. Nothing remains on this server.');
    }

    /** Auto-detect check type from a raw query. */
    private function detectType(string $q): string
    {
        $q = trim($q);
        if ($q === '') {
            return 'email';
        }
        if (filter_var($q, FILTER_VALIDATE_EMAIL)) {
            return 'email';
        }
        if (filter_var($q, FILTER_VALIDATE_IP)) {
            return 'ip';
        }
        if (preg_match('/^\+?\d[\d\s().-]{6,20}$/', $q)) {
            return 'phone';
        }
        $stripped = strtolower((string) preg_replace('/^https?:\/\//', '', $q));
        $stripped = (string) preg_replace('/\/.*$/', '', $stripped);
        if (str_contains($stripped, '.') && filter_var($stripped, FILTER_VALIDATE_DOMAIN)) {
            return 'domain';
        }

        return 'username';
    }

    /** Source directory for the page footer (transparency). */
    private function sourceDirectory(): array
    {
        $out = [];
        foreach (OsintCheckService::SOURCES as $cls) {
            $src = app($cls);
            $out[] = ['key' => $src->key(), 'label' => $src->label(), 'category' => $src->category()];
        }

        return $out;
    }
}
