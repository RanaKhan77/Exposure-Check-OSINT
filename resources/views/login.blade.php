<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>Sign in — Exposure-Check-OSINT</title>
    <link rel="icon" href="favicon.svg" type="image/svg+xml">
    <style>
        :root { --bg:#0B1220; --card:#111C33; --line:#22314F; --text:#E5EDFF; --muted:#94A6C8; --accent:#22D3EE; --accent2:#3B82F6; }
        * { box-sizing: border-box; }
        body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:var(--bg); color:var(--text);
               font:14px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
               background-image: radial-gradient(900px 400px at 80% -10%, rgba(59,130,246,.16), transparent 60%), radial-gradient(700px 350px at 0% 100%, rgba(34,211,238,.10), transparent 55%); }
        .box { width: 380px; max-width: calc(100vw - 40px); background: var(--card); border:1px solid var(--line); border-radius:16px; padding:30px; }
        .brand { display:flex; gap:12px; align-items:center; margin-bottom:6px; }
        .logo { width:42px; height:42px; border-radius:12px; background:linear-gradient(135deg,#22D3EE,#3B82F6); display:flex; align-items:center; justify-content:center; font-size:20px; }
        h1 { font-size:18px; margin:0; }
        .sub { color:var(--muted); font-size:12.5px; margin:10px 0 20px; }
        label { display:block; font-size:12px; font-weight:700; color:var(--muted); margin:0 0 6px; }
        input { width:100%; background:#0F172A; color:var(--text); border:1px solid var(--line); border-radius:10px; padding:12px 14px; font-size:14px; outline:none; }
        input:focus { border-color: var(--accent2); box-shadow:0 0 0 3px rgba(59,130,246,.18); }
        button { width:100%; margin-top:16px; background:linear-gradient(135deg,#22D3EE,#3B82F6); color:#06121F; font-weight:800; border:0; border-radius:10px; padding:12px; font-size:14px; cursor:pointer; }
        button:hover { filter:brightness(1.1); }
        .err { background:rgba(248,113,113,.12); border:1px solid rgba(248,113,113,.3); color:#F87171; border-radius:9px; padding:10px 13px; font-size:12.5px; margin-bottom:14px; }
        .hint { color:var(--muted); font-size:11.5px; margin-top:16px; text-align:center; }
    </style>
</head>
<body>
    <div class="box">
        <div class="brand"><div class="logo">🛡️</div><div><h1>Exposure-Check-OSINT</h1></div></div>
        <p class="sub">Single-admin sign in. The password is set in <code>ADMIN_PASSWORD</code> inside your <code>.env</code> (install.sh generated it on first boot).</p>
        @if ($errors->any()) <div class="err">{{ $errors->first() }}</div> @endif
        <form method="POST" action="{{ route('login.attempt') }}">
            @csrf
            <label for="password">Admin password</label>
            <input id="password" type="password" name="password" required autofocus autocomplete="current-password">
            <button type="submit">Sign in</button>
        </form>
        <p class="hint">Self-hosted · keyless sources · no AI · results stay on this server</p>
    </div>
</body>
</html>
