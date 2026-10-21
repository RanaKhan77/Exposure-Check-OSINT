<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Services\CommunityLicenseService;
use Illuminate\Http\Request;

class LicenseController extends Controller
{
    public function __construct(private readonly CommunityLicenseService $license)
    {
    }

    public function index()
    {
        $row = $this->license->state();

        return view('license', [
            'title' => 'License — Exposure-Check-OSINT',
            'row' => $row,
            'status' => $this->license->status(),
            'serverUrl' => $this->license->serverUrl(),
            'installId' => $this->license->installId(),
            'trialDaysLeft' => $row->trialDaysLeft(),
        ]);
    }

    public function activate(Request $request)
    {
        $data = $request->validate(['license_key' => ['required', 'string', 'max:64']]);
        $result = $this->license->activate((string) $data['license_key']);

        return redirect()->route('license')
            ->with($result['ok'] ? 'status' : 'error', $result['message']);
    }

    public function deactivate(Request $request)
    {
        $this->license->deactivate();

        return redirect()->route('license')->with('status', 'License deactivated on this install.');
    }
}
