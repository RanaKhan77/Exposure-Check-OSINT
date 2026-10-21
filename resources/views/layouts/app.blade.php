<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <meta name="robots" content="noindex, nofollow">
    <title>@yield('title', 'Exposure-Check-OSINT')</title>
    <link rel="icon" href="{{ asset('favicon.svg') }}" type="image/svg+xml">
    <style>
        :root {
            --bg: #0B1220; --bg-soft: #0F172A; --card: #111C33; --card-2: #16233F;
            --line: #22314F; --line-soft: #1A2743;
            --text: #E5EDFF; --muted: #94A6C8; --dim: #64748B;
            --accent: #22D3EE; --accent-2: #3B82F6; --accent-soft: rgba(34, 211, 238, .12);
            --red: #F87171; --red-deep: #EF4444; --amber: #FBBF24; --green: #34D399; --violet: #A78BFA;
            --radius: 14px; --radius-sm: 9px;
        }
        * { box-sizing: border-box; }
        html, body { margin: 0; padding: 0; }
        body {
            background: var(--bg); color: var(--text);
            font: 14px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            min-height: 100vh;
            background-image: radial-gradient(1200px 500px at 80% -10%, rgba(59, 130, 246, .14), transparent 60%),
                              radial-gradient(900px 420px at -10% 0%, rgba(34, 211, 238, .10), transparent 55%);
        }
        a { color: var(--accent); text-decoration: none; }
        a:hover { text-decoration: underline; }
        .wrap { max-width: 1080px; margin: 0 auto; padding: 0 20px 60px; }

        /* nav */
        .nav { border-bottom: 1px solid var(--line-soft); background: rgba(11, 18, 32, .85); backdrop-filter: blur(8px); position: sticky; top: 0; z-index: 50; }
        .nav-in { max-width: 1080px; margin: 0 auto; padding: 12px 20px; display: flex; align-items: center; gap: 18px; }
        .brand { display: flex; align-items: center; gap: 10px; font-weight: 800; letter-spacing: .2px; color: var(--text); font-size: 15px; }
        .brand:hover { text-decoration: none; }
        .brand .dot { width: 26px; height: 26px; border-radius: 8px; background: linear-gradient(135deg, #22D3EE, #3B82F6); display: inline-flex; align-items: center; justify-content: center; font-size: 14px; }
        .nav-links { margin-left: auto; display: flex; gap: 4px; align-items: center; flex-wrap: wrap; }
        .nav-links a { color: var(--muted); padding: 7px 12px; border-radius: 8px; font-weight: 600; font-size: 13px; }
        .nav-links a:hover { color: var(--text); background: var(--card); text-decoration: none; }
        .nav-links a.active { color: var(--accent); background: var(--accent-soft); }

        /* generic */
        .card { background: var(--card); border: 1px solid var(--line-soft); border-radius: var(--radius); padding: 20px; }
        h1 { font-size: 24px; margin: 28px 0 6px; letter-spacing: -.3px; }
        .sub { color: var(--muted); margin: 0 0 22px; font-size: 13.5px; }
        .btn { display: inline-flex; align-items: center; gap: 8px; background: linear-gradient(135deg, #22D3EE, #3B82F6); color: #06121F; font-weight: 800; border: 0; border-radius: 10px; padding: 10px 18px; font-size: 13.5px; cursor: pointer; transition: filter .15s; }
        .btn:hover { filter: brightness(1.1); }
        .btn[disabled] { opacity: .55; cursor: not-allowed; }
        .btn-ghost { background: var(--card-2); color: var(--text); border: 1px solid var(--line); }
        .btn-danger { background: linear-gradient(135deg, #F87171, #EF4444); color: #1A0505; }
        .chip { display: inline-flex; align-items: center; gap: 6px; border-radius: 999px; padding: 4px 12px; font-size: 12px; font-weight: 700; }
        .chip-red { background: rgba(248, 113, 113, .14); color: var(--red); }
        .chip-green { background: rgba(52, 211, 153, .13); color: var(--green); }
        .chip-amber { background: rgba(251, 191, 36, .13); color: var(--amber); }
        .chip-blue { background: rgba(59, 130, 246, .15); color: #7EB3FF; }
        .chip-gray { background: var(--card-2); color: var(--muted); }
        input[type=text], input[type=password], input[type=number], select {
            background: var(--bg-soft); color: var(--text); border: 1px solid var(--line); border-radius: 10px;
            padding: 11px 14px; font-size: 14px; width: 100%; outline: none;
        }
        input:focus, select:focus { border-color: var(--accent-2); box-shadow: 0 0 0 3px rgba(59, 130, 246, .18); }
        label { display: block; font-weight: 700; font-size: 12.5px; color: var(--muted); margin: 14px 0 6px; }
        .flash { border-radius: var(--radius-sm); padding: 12px 16px; margin: 14px 0; font-weight: 600; font-size: 13px; }
        .flash-ok { background: rgba(52, 211, 153, .12); color: var(--green); border: 1px solid rgba(52, 211, 153, .25); }
        .flash-err { background: rgba(248, 113, 113, .12); color: var(--red); border: 1px solid rgba(248, 113, 113, .25); }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; font-size: 11.5px; text-transform: uppercase; letter-spacing: .6px; color: var(--dim); padding: 10px 12px; border-bottom: 1px solid var(--line-soft); }
        td { padding: 12px; border-bottom: 1px solid var(--line-soft); font-size: 13.5px; vertical-align: middle; }
        tr:hover td { background: rgba(22, 35, 63, .5); }
        .footer { margin-top: 46px; padding-top: 18px; border-top: 1px solid var(--line-soft); color: var(--dim); font-size: 12px; display: flex; gap: 16px; flex-wrap: wrap; }
        @media (max-width: 720px) { .nav-in { flex-wrap: wrap; } }
    </style>
    @stack('head')
</head>
<body>
<nav class="nav">
    <div class="nav-in">
        <a class="brand" href="{{ route('dashboard') }}"><span class="dot">🛡️</span> Exposure-Check-OSINT</a>
        <div class="nav-links">
            <a href="{{ route('dashboard') }}" class="{{ request()->routeIs('dashboard') ? 'active' : '' }}">Check</a>
            <a href="{{ route('history') }}" class="{{ request()->routeIs('history') ? 'active' : '' }}">History</a>
            <a href="{{ route('settings') }}" class="{{ request()->routeIs('settings') ? 'active' : '' }}">Settings</a>
            <a href="{{ route('license') }}" class="{{ request()->routeIs('license') ? 'active' : '' }}">License</a>
            <form method="POST" action="{{ route('logout') }}" style="margin:0">@csrf<button style="background:none;border:0;color:var(--muted);font-weight:600;font-size:13px;cursor:pointer">Sign out</button></form>
        </div>
    </div>
</nav>
<div class="wrap">
    @if (session('status')) <div class="flash flash-ok">{{ session('status') }}</div> @endif
    @if (session('error')) <div class="flash flash-err">{{ session('error') }}</div> @endif
    @yield('content')
    <div class="footer">
        <span>Exposure-Check-OSINT v{{ config('app.version') }} — self-hosted, keyless, no AI.</span>
        <a href="https://github.com/RanaKhan77/Exposure-Check-OSINT" target="_blank" rel="noopener">GitHub</a>
        <a href="https://github.com/RanaKhan77/Website-Vulnerability-Scanner" target="_blank" rel="noopener">Need domain/website scanning? The 200-scanner CE →</a>
    </div>
</div>
@stack('scripts')
</body>
</html>
