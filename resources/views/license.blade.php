@extends('layouts.app')

@section('content')
<h1>License</h1>
<p class="sub">The Community Edition license is deliberately simple and honest — not DRM. It exists for voluntary install tracking and free premium update notifications. It is easy to audit and easy to remove (this is open source).</p>

<div class="card">
    <div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-bottom:18px">
        @if ($status === 'licensed')
            <span class="chip chip-green">✔ Activated — update notifications on</span>
        @elseif ($status === 'key-revoked')
            <span class="chip chip-amber">Key revoked — checks unaffected</span>
        @else
            <span class="chip chip-blue">No key — fully functional, forever</span>
        @endif
        <span class="chip chip-gray">install: {{ $installId }}</span>
    </div>

    @if ($status === 'unlicensed')
        <p style="background:#e8f7ee;border:1px solid #bfe6cf;border-radius:8px;padding:12px 14px;color:#14532d">
            <strong>No key required.</strong> Every check runs forever, free — there is no trial,
            no countdown and no phone-home. The optional free key below only adds update
            notifications (and supports the project's roadmap counter).
        </p>
    @endif

    @if ($status === 'key-revoked')
        <p style="background:#fef6e7;border:1px solid #f0dfb8;border-radius:8px;padding:12px 14px;color:#78350f">
            <strong>This key was revoked.</strong> Nothing breaks: checks, history, reports and
            exports keep working exactly as before — only update notifications stopped. Grab a
            fresh free key below if you want them back.
        </p>
    @endif

    <table>
        <tr><th style="width:220px">Status</th><td>{{ ucfirst($status) }}</td></tr>
        <tr><th>License key</th><td>{{ $row->license_key ?? '— (none, optional)' }}</td></tr>
        <tr><th>Installed at</th><td>{{ $row->trial_started_at?->format('Y-m-d H:i') ?? '—' }}</td></tr>
        <tr><th>Activated at</th><td>{{ $row->activated_at?->format('Y-m-d H:i') ?? '—' }}</td></tr>
        <tr><th>Last validated</th><td>{{ $row->last_validated_at?->format('Y-m-d H:i') ?? '—' }}</td></tr>
    </table>

    <div style="margin-top:22px;display:flex;gap:26px;flex-wrap:wrap">
        <div style="flex:1;min-width:280px">
            <h2 style="font-size:14px;margin:0 0 8px">Activate a free key (optional)</h2>
            <p style="color:var(--muted);font-size:12.5px;margin:0 0 12px">
                Request a free Community key (format <code>2MNY-EC-XXXX-XXXX-XXXX-XXXX</code>) at
                <a href="{{ $serverUrl }}/community-license" target="_blank" rel="noopener">{{ $serverUrl }}/community-license</a>
                — takes about 30 seconds. The key powers update notifications and the project's
                install counter, nothing else. All checks keep working with or without it, online
                or offline.
            </p>
            <form method="POST" action="{{ route('license.activate') }}" style="display:flex;gap:10px;flex-wrap:wrap">
                @csrf
                <input type="text" name="license_key" placeholder="2MNY-EC-XXXX-XXXX-XXXX-XXXX" style="flex:1;min-width:230px" maxlength="64" required>
                <button class="btn" type="submit">Activate</button>
            </form>
        </div>
        <div style="flex:0 0 auto">
            @if ($row->status === 'licensed')
                <form method="POST" action="{{ route('license.deactivate') }}">
                    @csrf
                    <button class="btn btn-ghost" type="submit">Deactivate on this install</button>
                </form>
            @endif
        </div>
    </div>
</div>
@endsection
