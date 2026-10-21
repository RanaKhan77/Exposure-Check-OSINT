@extends('layouts.app')

@section('content')
<h1>License</h1>
<p class="sub">The Community Edition license is deliberately simple and honest — not DRM. It exists for install tracking and free premium update notifications. It is easy to audit and easy to remove (this is open source).</p>

<div class="card">
    <div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-bottom:18px">
        @if ($status === 'licensed')
            <span class="chip chip-green">✔ Licensed</span>
        @elseif ($status === 'trial')
            <span class="chip chip-blue">Trial — {{ $trialDaysLeft }} day(s) left</span>
        @elseif ($status === 'grace')
            <span class="chip chip-amber">Grace — license server unreachable (still working)</span>
        @else
            <span class="chip chip-red">Blocked — activate a free key to run new checks</span>
        @endif
        <span class="chip chip-gray">install: {{ $installId }}</span>
    </div>

    <table>
        <tr><th style="width:220px">Status</th><td>{{ ucfirst($status) }}</td></tr>
        <tr><th>License key</th><td>{{ $row->license_key ?? '— (trial)' }}</td></tr>
        <tr><th>Trial started</th><td>{{ $row->trial_started_at?->format('Y-m-d H:i') ?? '—' }}</td></tr>
        <tr><th>Trial ends</th><td>{{ $row->trial_ends_at?->format('Y-m-d H:i') ?? '—' }}</td></tr>
        <tr><th>Activated at</th><td>{{ $row->activated_at?->format('Y-m-d H:i') ?? '—' }}</td></tr>
        <tr><th>Last validated</th><td>{{ $row->last_validated_at?->format('Y-m-d H:i') ?? '—' }}</td></tr>
    </table>

    <div style="margin-top:22px;display:flex;gap:26px;flex-wrap:wrap">
        <div style="flex:1;min-width:280px">
            <h2 style="font-size:14px;margin:0 0 8px">Activate a free key</h2>
            <p style="color:var(--muted);font-size:12.5px;margin:0 0 12px">
                Request a free Community key (format <code>2MNY-EC-XXXX-XXXX-XXXX-XXXX</code>) at
                <a href="{{ $serverUrl }}/community-license" target="_blank" rel="noopener">{{ $serverUrl }}/community-license</a>
                — takes about 30 seconds. New checks are blocked after the trial until a key is activated;
                history and every other page keep working. 7-day offline grace for licensed installs.
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
