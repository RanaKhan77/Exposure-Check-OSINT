@extends('layouts.app')

@section('content')
<h1>Settings</h1>
<p class="sub">Own-use tuning. Quotas protect the third-party sources as much as this install; the honest UA string is sent with every source lookup.</p>

<div class="card">
    <form method="POST" action="{{ route('settings.save') }}">
        @csrf
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:0 22px">
            <div>
                <label for="daily_check_limit">Daily check limit</label>
                <input id="daily_check_limit" type="number" name="daily_check_limit" min="1" max="100000" value="{{ old('daily_check_limit', $values['daily_check_limit']) }}" required>
            </div>
            <div>
                <label for="burst_per_minute">Burst limit (checks / minute)</label>
                <input id="burst_per_minute" type="number" name="burst_per_minute" min="2" max="120" value="{{ old('burst_per_minute', $values['burst_per_minute']) }}" required>
            </div>
            <div>
                <label for="cache_ttl_seconds">Result cache TTL (seconds)</label>
                <input id="cache_ttl_seconds" type="number" name="cache_ttl_seconds" min="60" max="86400" value="{{ old('cache_ttl_seconds', $values['cache_ttl_seconds']) }}" required>
                <p style="color:var(--dim);font-size:11.5px;margin:6px 0 0">Breach data changes slowly — 1800s (30 min) is a good default.</p>
            </div>
            <div>
                <label for="user_agent">User-Agent for source lookups</label>
                <input id="user_agent" type="text" name="user_agent" maxlength="300" value="{{ old('user_agent', $values['user_agent']) }}" required>
            </div>
        </div>

        <h2 style="font-size:14px;margin:26px 0 6px">Sources</h2>
        <p style="color:var(--muted);font-size:12.5px;margin:0 0 12px">Unchecked sources are skipped entirely (no requests sent to them). All {{ count($sources) }} are keyless and read-only.</p>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:8px">
            @foreach ($sources as $s)
                <label style="display:flex;gap:10px;align-items:center;background:var(--bg-soft);border:1px solid var(--line);border-radius:10px;padding:10px 13px;margin:0;cursor:pointer;font-weight:600;color:var(--text);font-size:12.5px">
                    <input type="checkbox" name="sources[]" value="{{ $s['key'] }}" @checked($s['enabled']) style="width:16px;height:16px;accent-color:#22D3EE">
                    <span>{{ $s['label'] }}<br><span style="color:var(--dim);font-size:11px">{{ $s['category'] }}</span></span>
                </label>
            @endforeach
        </div>

        <div style="margin-top:22px">
            <button class="btn" type="submit">Save settings</button>
        </div>
    </form>
</div>
@endsection
