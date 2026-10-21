<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ $title }}</title>
    <style>
        :root { --text:#0F172A; --muted:#475569; --line:#E2E8F0; --card:#F8FAFC; --red:#B91C1C; --amber:#B45309; --green:#166534; }
        * { box-sizing:border-box; }
        body { font:13.5px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color:var(--text); margin:0; background:#fff; }
        .page { max-width:860px; margin:0 auto; padding:44px 28px 64px; }
        .head { border-bottom:3px solid #0F172A; padding-bottom:18px; margin-bottom:24px; display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap; }
        h1 { font-size:22px; margin:0 0 4px; }
        .meta { color:var(--muted); font-size:12px; }
        .scorebox { display:flex; gap:22px; align-items:center; background:var(--card); border:1px solid var(--line); border-radius:12px; padding:18px 22px; margin-bottom:22px; }
        .big { font-size:40px; font-weight:800; line-height:1; }
        table { width:100%; border-collapse:collapse; margin:10px 0 26px; }
        th { text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:var(--muted); padding:8px 10px; border-bottom:2px solid var(--line); }
        td { padding:9px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
        .chip { display:inline-block; border-radius:999px; padding:2px 10px; font-size:11px; font-weight:700; }
        .hit { background:#FEE2E2; color:var(--red); }
        .clean { background:#DCFCE7; color:var(--green); }
        .unavail { background:#F1F5F9; color:#64748B; }
        .sev-critical { background:#FEE2E2; color:var(--red); }
        .sev-high { background:#FFEDD5; color:var(--amber); }
        .sev-medium { background:#FEF3C7; color:var(--amber); }
        .sev-low { background:#DBEAFE; color:#1D4ED8; }
        .sev-info { background:#F1F5F9; color:#64748B; }
        .footer { border-top:1px solid var(--line); margin-top:34px; padding-top:14px; color:var(--muted); font-size:11px; }
        .print-btn { position:fixed; right:22px; top:22px; background:#0F172A; color:#fff; border:0; border-radius:9px; padding:9px 16px; font-weight:700; cursor:pointer; }
        @media print { .print-btn { display:none; } body { font-size:12px; } .page { padding:0; } }
    </style>
</head>
<body>
<button class="print-btn" onclick="window.print()">🖨 Print / Save as PDF</button>
<div class="page">
    <div class="head">
        <div>
            <h1>Exposure Report — {{ $check->identifier_masked }}</h1>
            <div class="meta">Exposure-Check-OSINT v{{ config('app.version') }} (self-hosted) · Check #{{ $check->id }} · {{ $check->created_at?->format('Y-m-d H:i') }} UTC</div>
        </div>
        <div class="meta">Generated locally — no third party received this document.</div>
    </div>

@php
    $score = $check->exposure_score;
    $riskLabel = 'Not assessed';
    if ($score !== null) {
        if ($check->hits === 0) { $riskLabel = 'No exposure found'; }
        elseif ($score < 40) { $riskLabel = 'Critical exposure'; }
        elseif ($score < 70) { $riskLabel = 'Elevated exposure'; }
        elseif ($score < 95) { $riskLabel = 'Minor exposure'; }
        else { $riskLabel = 'Low exposure'; }
    }
@endphp

    <div class="scorebox">
        <div>
            <div class="big" style="color:{{ $score === null ? '#64748B' : ($score < 40 ? '#B91C1C' : ($score < 70 ? '#B45309' : '#166534')) }}">{{ $score ?? '–' }}@if($score !== null)<span style="font-size:16px;color:#64748B"> / 100</span>@endif</div>
            <div class="meta">exposure score · 100 = clean, 0 = maximum exposure</div>
        </div>
        <div>
            <div style="font-weight:800;font-size:15px;color:{{ $score === null ? '#64748B' : ($score < 40 ? '#B91C1C' : ($score < 70 ? '#B45309' : '#166534')) }}">{{ strtoupper($riskLabel) }}</div>
            <div style="font-weight:800;margin-top:6px">{{ $check->hits }} exposure signal(s) across {{ $check->total_sources }} assessed sources</div>
            <div class="meta">Type: {{ $check->type }} · Identifier shown masked by design.</div>
        </div>
    </div>

    <h2 style="font-size:15px">Source results</h2>
    <table>
        <tr><th style="width:26%">Source</th><th style="width:12%">Status</th><th>Summary</th></tr>
        @foreach (($check->results ?? []) as $src)
            <tr>
                <td><b>{{ $src['label'] ?? $src['key'] }}</b><div class="meta">{{ $src['category'] ?? '' }}</div></td>
                <td><span class="chip {{ $src['status'] === 'hit' ? 'hit' : ($src['status'] === 'clean' ? 'clean' : 'unavail') }}">{{ $src['status'] }}</span>
                    @if ($src['status'] === 'hit' && !empty($src['severity']))<div style="margin-top:4px"><span class="chip sev-{{ $src['severity'] }}">{{ $src['severity'] }}</span></div>@endif</td>
                <td>{{ $src['summary'] ?? '' }}</td>
            </tr>
        @endforeach
        @if (empty($check->results))
            <tr><td colspan="3" style="color:#64748B">No per-source details stored for this check (password checks store no result data by design — matching happens in your browser).</td></tr>
        @endif
    </table>

    <div class="footer">
        Exposure-Check-OSINT — self-hosted personal exposure checker (Apache-2.0). Read-only lookups against public
        sources; results reflect publicly available data at check time. Identifiers you are authorized to check only.
        Companion product for domain/website security: Website Vulnerability Scanner CE on GitHub.
    </div>
</div>
</body>
</html>
