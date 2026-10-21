<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;

class AuthController extends Controller
{
    public function showLogin(Request $request)
    {
        if ($request->session()->get('admin_authenticated') === true) {
            return redirect()->route('dashboard');
        }

        return view('login', ['title' => 'Sign in — Exposure-Check-OSINT']);
    }

    public function login(Request $request)
    {
        $credentials = $request->validate([
            'password' => ['required', 'string'],
        ]);

        $key = 'login:' . $request->ip();
        if (RateLimiter::tooManyAttempts($key, 5)) {
            return back()->withErrors(['password' => 'Too many attempts — try again in ' . RateLimiter::availableIn($key) . ' seconds.']);
        }
        RateLimiter::hit($key, 300);

        $expected = (string) config('app.admin_password', '');
        if ($expected === '' || !hash_equals($expected, (string) $credentials['password'])) {
            return back()->withErrors(['password' => 'Incorrect password.'])->withInput($request->only('remember'));
        }

        RateLimiter::clear($key);
        $request->session()->regenerate();
        $request->session()->put('admin_authenticated', true);

        return redirect()->intended(route('dashboard'));
    }

    public function logout(Request $request)
    {
        // Fully destroy the session record (regenerate() alone keeps the old
        // one alive until expiry) and issue a fresh CSRF token.
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('login');
    }
}
