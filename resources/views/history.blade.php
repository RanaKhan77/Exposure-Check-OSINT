@extends('layouts.app')

@section('content')
<h1>History</h1>
<p class="sub">Past checks, stored locally in this install's SQLite database only. Identifiers are kept as salted hashes + masked forms — delete anything, any time.</p>

<div class="card">
    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px">
        <a class="chip chip-blue" href="{{ route('history') }}">All</a>
        @foreach (['email', 'username', 'phone', 'password', 'ip'] as $t)
            <a class="chip {{ request('type') === $t ? 'chip-blue' : 'chip-gray' }}" href="{{ route('history', ['type' => $t]) }}">{{ $t }}</a>
        @endforeach
        <form method="POST" action="{{ route('history.purge') }}" style="margin-left:auto" onsubmit="return confirm('Delete ALL stored checks? This cannot be undone.')">
            @csrf
            <button class="btn btn-danger" type="submit" style="padding:7px 14px;font-size:12px">Purge all</button>
        </form>
    </div>

    @if ($checks->isEmpty())
        <p style="color:var(--muted);padding:26px;text-align:center">No checks yet — run your first one on the <a href="{{ route('dashboard') }}">Check page</a>.</p>
    @else
        <div style="overflow-x:auto">
        <table>
            <tr><th>#</th><th>Identifier</th><th>Type</th><th>Sources</th><th>Hits</th><th>Score</th><th>When</th><th></th></tr>
            @foreach ($checks as $c)
                <tr>
                    <td style="color:var(--dim)">{{ $c->id }}</td>
                    <td><b>{{ $c->identifier_masked }}</b></td>
                    <td><span class="chip chip-gray">{{ $c->type }}</span></td>
                    <td>{{ $c->total_sources }}</td>
                    <td>@if ($c->hits > 0)<span class="chip chip-red">{{ $c->hits }}</span>@else<span class="chip chip-green">0</span>@endif</td>
                    <td>@if ($c->exposure_score !== null)
                            <b style="color: {{ $c->exposure_score < 40 ? 'var(--red)' : ($c->exposure_score < 70 ? 'var(--amber)' : 'var(--green)') }}">{{ $c->exposure_score }}</b>
                        @else <span style="color:var(--dim)">–</span>@endif</td>
                    <td style="color:var(--muted);font-size:12px">{{ $c->created_at?->format('M j, Y H:i') }}</td>
                    <td style="white-space:nowrap">
                        <a class="btn btn-ghost" style="padding:5px 11px;font-size:11.5px" href="{{ route('report', $c) }}" target="_blank" rel="noopener">Report</a>
                        <form method="POST" action="{{ route('history.destroy', $c) }}" style="display:inline" onsubmit="return confirm('Delete this check?')">
                            @csrf @method('DELETE')
                            <button class="btn btn-ghost" type="submit" style="padding:5px 11px;font-size:11.5px;color:var(--red)">Delete</button>
                        </form>
                    </td>
                </tr>
            @endforeach
        </table>
        </div>
        <div style="margin-top:14px">{{ $checks->links() }}</div>
    @endif
</div>
@endsection
