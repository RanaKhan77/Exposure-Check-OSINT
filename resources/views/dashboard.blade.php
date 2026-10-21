@extends('layouts.app')

@section('content')
<h1>Exposure Check</h1>
<p class="sub">Check if an email, username, phone number, password or IP is exposed — breaches, stealer logs, linked accounts, public data. Read-only lookups against 18 keyless sources. Identifiers you are authorized to check only.</p>

<div class="card" style="padding:22px">
    <form id="ox-form" autocomplete="off">
        <div id="ox-tabs" style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">
            <button type="button" class="ox-tab active" data-type="email">📧 Email</button>
            <button type="button" class="ox-tab" data-type="username">👤 Username</button>
            <button type="button" class="ox-tab" data-type="phone">📱 Phone</button>
            <button type="button" class="ox-tab" data-type="password">🔑 Password</button>
            <button type="button" class="ox-tab" data-type="ip">🌐 IP</button>
        </div>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
            <input id="ox-input" type="text" placeholder="email@example.com" style="flex:1;min-width:240px" value="{{ $initialQuery }}" autofocus>
            <button class="btn" id="ox-go" type="submit">Check exposure →</button>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;align-items:center">
            <span id="ox-typedetect" class="chip chip-blue">type: email</span>
            <span class="chip chip-gray">{{ number_format($stats['breaches']) }}+ breaches indexed</span>
            <span class="chip chip-gray">{{ number_format($stats['records'] / 1000000000, 1) }}B+ leaked records</span>
            <span class="chip chip-gray">{{ number_format($stats['infections'] / 1000000) }}M stealer infections</span>
            <span class="chip chip-gray">{{ $stats['sources'] }} live sources</span>
            <span id="ox-quota" class="chip chip-green" style="margin-left:auto" hidden></span>
        </div>
        <p id="ox-err" class="flash flash-err" hidden style="margin:12px 0 0"></p>
        <p style="color:var(--dim);font-size:11.5px;margin:12px 0 0">
            Password checks hash your input in your browser with SHA-1 and send only a 5-character prefix —
            your password never leaves this device, not even hashed in full. See docs/PRIVACY.md.
        </p>
    </form>
</div>

<div id="ox-result" hidden style="margin-top:22px">
    <div class="card" style="display:flex;gap:26px;align-items:center;flex-wrap:wrap">
        <div style="position:relative;width:130px;height:130px;flex:0 0 auto">
            <svg viewBox="0 0 130 130" width="130" height="130">
                <circle cx="65" cy="65" r="56" fill="none" stroke="#1A2743" stroke-width="11"/>
                <circle id="ox-gauge" cx="65" cy="65" r="56" fill="none" stroke="#34D399" stroke-width="11"
                        stroke-linecap="round" stroke-dasharray="351.86" stroke-dashoffset="351.86"
                        transform="rotate(-90 65 65)" style="transition:stroke-dashoffset .9s ease, stroke .4s"/>
                <text id="ox-score" x="65" y="62" text-anchor="middle" font-size="26" font-weight="800" fill="#E5EDFF">–</text>
                <text x="65" y="82" text-anchor="middle" font-size="10" fill="#94A6C8">exposure score</text>
            </svg>
        </div>
        <div style="flex:1;min-width:240px">
            <div style="font-size:13px;color:var(--muted)">Checked identifier</div>
            <div id="ox-masked" style="font-size:19px;font-weight:800;margin:2px 0 8px">–</div>
            <div id="ox-risk" style="font-size:15px;font-weight:800;color:var(--green)">–</div>
            <div id="ox-risk-sub" style="color:var(--muted);font-size:12.5px;margin-top:4px">–</div>
            <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
                <span id="ox-pill-hits" class="chip chip-red" hidden></span>
                <span id="ox-pill-clean" class="chip chip-green" hidden>no exposure signals found</span>
                <span id="ox-pill-sources" class="chip chip-gray"></span>
            </div>
        </div>
        <a id="ox-report-link" class="btn btn-ghost" href="#" target="_blank" rel="noopener" hidden>📄 Open report</a>
        <a id="ox-export-json" class="btn btn-ghost" href="#" hidden>⬇ JSON</a>
        <a id="ox-export-csv" class="btn btn-ghost" href="#" hidden>⬇ CSV</a>
    </div>

    <div id="ox-password-result" class="card" hidden style="margin-top:14px"></div>
    <div id="ox-cards" style="margin-top:14px"></div>
</div>

<div class="card" style="margin-top:26px">
    <div style="font-weight:800;margin-bottom:4px">🔎 All {{ count($sources) }} sources in this install</div>
    <p style="color:var(--muted);font-size:12.5px;margin:0 0 12px">Every source is keyless (no API keys, no accounts), read-only, and can be disabled on the Settings page. Full per-source details: docs/SOURCES.md.</p>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
        @foreach ($sources as $s)
            <span class="chip chip-gray" title="{{ $s['category'] }}">{{ $s['label'] }}</span>
        @endforeach
    </div>
</div>
@endsection

@push('scripts')
<script>
(function () {
    'use strict';
    var input = document.getElementById('ox-input');
    var form = document.getElementById('ox-form');
    var goBtn = document.getElementById('ox-go');
    var errEl = document.getElementById('ox-err');
    var typeEl = document.getElementById('ox-typedetect');
    var quotaEl = document.getElementById('ox-quota');
    var resultsEl = document.getElementById('ox-result');
    var cardsEl = document.getElementById('ox-cards');
    var type = 'email';
    var fullHash = '';

    var CATS = {
        stealer:    { label: 'Credential Exposure — Stealer Logs', color: '#F87171' },
        breach:     { label: 'Breach Data & Leaked Credentials', color: '#FBBF24' },
        reputation: { label: 'Reputation Signals', color: '#60A5FA' },
        profile:    { label: 'Profile & Social Footprint', color: '#A78BFA' },
        email:      { label: 'Email Intelligence', color: '#34D399' },
        infra:      { label: 'Infrastructure & Network', color: '#22D3EE' }
    };
    var CAT_ORDER = ['stealer', 'breach', 'profile', 'email', 'reputation', 'infra'];
    var SEV = { critical: ['Critical', '#F87171'], high: ['High', '#FB923C'], medium: ['Medium', '#FBBF24'], low: ['Low', '#60A5FA'], info: ['Info', '#94A6C8'] };

    function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
    function detectType(q) {
        q = q.trim();
        if (!q) return 'email';
        if (/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(q)) return 'email';
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(q)) return 'ip';
        // IPv6 literal (contains : and hex groups) — sources support it
        if (q.includes(':') && /^[0-9a-fA-F:]+$/.test(q) && (q.match(/:/g) || []).length >= 2) return 'ip';
        if (/^\+?\d[\d\s().-]{6,20}$/.test(q)) return 'phone';
        return 'username';
    }

    // Type tabs: email/username/phone/ip auto-detect inside the tab; password
    // is an explicit tab (a password can look like anything — never guessed).
    var PLACEHOLDERS = {
        email: 'email@example.com',
        username: 'username (e.g. johndoe)',
        phone: '+880 1712-345678',
        password: 'type a password — hashed in your browser, never sent',
        ip: '8.8.8.8 or 2606:4700::1111'
    };
    function setTab(t) {
        type = t;
        document.querySelectorAll('.ox-tab').forEach(function (b) {
            b.classList.toggle('active', b.getAttribute('data-type') === t);
        });
        input.type = (t === 'password') ? 'password' : 'text';
        input.placeholder = PLACEHOLDERS[t] || '';
        input.autocomplete = (t === 'password') ? 'new-password' : 'off';
        typeEl.textContent = 'type: ' + t;
    }
    document.querySelectorAll('.ox-tab').forEach(function (b) {
        b.addEventListener('click', function () { setTab(b.getAttribute('data-type')); });
    });
    function updateType() {
        if (type !== 'password') { type = detectType(input.value); typeEl.textContent = 'type: ' + type; }
    }
    input.addEventListener('input', updateType);
    setTab('{{ $initialType }}');

    function sha1Hex(str) {
        if (window.crypto && crypto.subtle) {
            var buf = new TextEncoder().encode(str);
            return crypto.subtle.digest('SHA-1', buf).then(function (h) {
                return Array.prototype.map.call(new Uint8Array(h), function (b) { return b.toString(16).padStart(2, '0'); }).join('').toUpperCase();
            });
        }
        return Promise.reject(new Error('Web Crypto unavailable — use a modern browser for password checks.'));
    }

    function updateQuota(q) {
        if (!q) { quotaEl.textContent = ''; quotaEl.hidden = true; return; }
        quotaEl.hidden = false;
        quotaEl.textContent = q.remaining + ' / ' + q.limit + ' checks left today';
        quotaEl.className = 'chip ' + (q.remaining > 0 ? 'chip-green' : 'chip-red');
    }

    function setGauge(score) {
        var g = document.getElementById('ox-gauge'), t = document.getElementById('ox-score');
        var C = 2 * Math.PI * 56;
        if (score === null || score === undefined || isNaN(score)) { g.setAttribute('stroke-dashoffset', C); t.textContent = '–'; g.setAttribute('stroke', '#94A6C8'); return; }
        var frac = Math.max(0, Math.min(1, (100 - score) / 100));
        g.setAttribute('stroke-dashoffset', String(C * (1 - frac)));
        g.setAttribute('stroke', score < 40 ? '#F87171' : score < 70 ? '#FBBF24' : '#34D399');
        t.textContent = String(score);
    }

    function letterTile(name) {
        var ch = (name || '?').trim().charAt(0).toUpperCase();
        return '<span class="ox-tile" style="background:#16233F;color:#94A6C8">' + esc(ch) + '</span>';
    }

    // staggered logo loader: max 4 concurrent /osint-logo requests
    function pumpLogos(root) {
        var imgs = Array.prototype.slice.call(root.querySelectorAll('img.lg[data-src]'));
        var i = 0, active = 0;
        function next() {
            while (active < 4 && i < imgs.length) {
                var im = imgs[i++];
                if (!im.getAttribute('data-src')) continue;
                active++;
                im.addEventListener('load', function () { active--; next(); }, { once: true });
                im.addEventListener('error', function (el) {
                    active--; next();
                    var t = el.target; if (t && t.parentElement) t.outerHTML = letterTile(t.getAttribute('data-site') || '?');
                }, { once: true });
                im.src = im.getAttribute('data-src'); im.removeAttribute('data-src');
            }
        }
        next();
    }

    function fieldRow(k, v) {
        if (v === null || v === undefined || v === '') return '';
        if (Array.isArray(v)) v = v.slice(0, 12).map(esc).join(', ') + (v.length > 12 ? ' +' + (v.length - 12) + ' more' : '');
        else if (typeof v === 'object') { try { v = esc(JSON.stringify(v).slice(0, 220)); } catch (e) { v = ''; } }
        else v = esc(v);
        return '<div class="ox-kv"><span>' + esc(k) + '</span><b>' + v + '</b></div>';
    }

    function renderCard(src, idx) {
        var sev = SEV[src.severity] || SEV.info;
        var statusChip = src.status === 'hit'
            ? '<span class="chip chip-red">exposed</span>'
            : (src.status === 'clean' ? '<span class="chip chip-green">clear</span>' : '<span class="chip chip-gray">unavailable</span>');
        var html =
            '<div class="ox-card open" style="animation-delay:' + Math.min(idx * 45, 400) + 'ms">' +
              '<div class="ox-head">' +
                '<span class="ox-src-logo">' + letterTile(src.label) + '</span>' +
                '<div class="ox-head-main">' +
                  '<div class="ox-title">' + esc(src.label) + (src.status === 'hit' ? ' <span class="chip" style="background:' + sev[1] + '22;color:' + sev[1] + '">' + sev[0] + '</span>' : '') + '</div>' +
                  '<div class="ox-summary">' + esc(src.summary) + '</div>' +
                '</div>' +
                '<div class="ox-head-side">' + statusChip + '</div>' +
              '</div>';

        // platform logo grid for found accounts (Maigret / probe / linked accounts)
        var d = src.data || {};
        var accounts = d.accounts || d.found_accounts || [];
        if (accounts.length) {
            html += '<div class="ox-accounts">';
            accounts.slice(0, 60).forEach(function (a) {
                var key = encodeURIComponent(String(a.site).toLowerCase().replace(/[^a-z0-9]+/g, '_'));
                var conf = a.confidence === 'confirmed' ? '<i class="ox-conf conf-c" title="confirmed: page content verified">&#10003;</i>'
                         : (a.confidence === 'probable' ? '<i class="ox-conf conf-p" title="probable: status code only">~</i>' : '');
                html += '<a class="ox-acct" href="' + esc(a.url || '#') + '" target="_blank" rel="noopener" title="' + esc(a.site) + '">' +
                        '<img class="lg" data-src="/osint-logo/' + key + '" alt="" data-site="' + esc(a.site) + '">' +
                        conf +
                        '<span>' + esc(a.site) + '</span></a>';
            });
            if (accounts.length > 60) html += '<span class="ox-acct more">+' + (accounts.length - 60) + ' more</span>';
            html += '</div>';
            if (d.found_confirmed !== undefined || d.found_probable !== undefined) {
                html += '<div class="ox-conf-line">' + (d.found_confirmed || 0) + ' confirmed (page content verified) &middot; ' + (d.found_probable || 0) + ' probable (status code only)</div>';
            }
        }

        // data fields (skip the big grid/binary ones)
        var skip = { accounts: 1, found_accounts: 1, profile_urls: 1, suffixes: 1, credential_lines: 1, unavailable_examples: 1, found_confirmed: 1, found_probable: 1 };
        var kv = '';
        Object.keys(d).forEach(function (k) { if (!skip[k]) kv += fieldRow(k, d[k]); });
        if (kv) html += '<div class="ox-body">' + kv + '</div>';
        html += '</div>';
        return html;
    }

    function renderResult(check) {
        resultsEl.hidden = false;
        document.getElementById('ox-masked').textContent = check.identifier_masked || '–';
        var s = check.summary || {};
        setGauge(s.exposure_score);
        var risk = document.getElementById('ox-risk');
        risk.textContent = s.risk_label || '–';
        risk.style.color = s.exposure_score === null ? '#94A6C8' : s.exposure_score < 40 ? '#F87171' : s.exposure_score < 70 ? '#FBBF24' : '#34D399';
        document.getElementById('ox-risk-sub').textContent =
            (s.sources_assessed || 0) + ' of ' + (s.sources_supporting || 0) + ' sources assessed' +
            (s.sources_unavailable > 0 ? ' (' + s.sources_unavailable + ' temporarily unavailable)' : '') +
            ' · ' + (s.hits > 0 ? s.hits + ' source(s) reported exposure' : 'no exposure signals found');
        var ph = document.getElementById('ox-pill-hits'), pc = document.getElementById('ox-pill-clean');
        ph.hidden = !(s.hits > 0); pc.hidden = s.hits > 0;
        if (s.hits > 0) ph.textContent = s.hits + ' exposure signal(s)';
        document.getElementById('ox-pill-sources').textContent = (s.sources_assessed || 0) + ' sources checked';

        var link = document.getElementById('ox-report-link');
        var ej = document.getElementById('ox-export-json'), ec = document.getElementById('ox-export-csv');
        if (check.check_id) {
            link.hidden = false; link.href = '/report/' + check.check_id;
            ej.hidden = false; ej.href = '/report/' + check.check_id + '/export/json';
            ec.hidden = false; ec.href = '/report/' + check.check_id + '/export/csv';
        } else { link.hidden = true; ej.hidden = true; ec.hidden = true; }

        // category sections
        var groups = {}, order = [];
        (check.sources || []).forEach(function (src) {
            var k = CATS[src.category] ? src.category : 'reputation';
            if (!groups[k]) { groups[k] = []; order.push(k); }
            groups[k].push(src);
        });
        order.sort(function (a, b) { return CAT_ORDER.indexOf(a) - CAT_ORDER.indexOf(b); });
        cardsEl.innerHTML = '';
        var idx = 0, first = true;
        order.forEach(function (k) {
            var list = groups[k];
            var nHit = 0, nClean = 0, nUn = 0;
            list.forEach(function (x) { if (x.status === 'hit') nHit++; else if (x.status === 'clean') nClean++; else nUn++; });
            var head = document.createElement('div');
            head.className = 'ox-sec-head' + (first ? '' : ' mt');
            first = false;
            head.innerHTML = '<span style="color:' + CATS[k].color + ';font-weight:800;font-size:13px">' + CATS[k].label + '</span>' +
                '<span style="display:flex;gap:6px;flex-wrap:wrap">' +
                (nHit ? '<span class="chip chip-red">' + nHit + ' exposed</span>' : '') +
                (nClean ? '<span class="chip chip-green">' + nClean + ' clear</span>' : '') +
                (nUn ? '<span class="chip chip-gray">' + nUn + ' unavailable</span>' : '') +
                '<span class="chip chip-gray">' + list.length + ' source' + (list.length > 1 ? 's' : '') + '</span></span>';
            cardsEl.appendChild(head);
            var wrap = document.createElement('div');
            wrap.className = 'ox-sec';
            wrap.innerHTML = list.map(function (src) { return renderCard(src, idx++); }).join('');
            cardsEl.appendChild(wrap);
        });
        pumpLogos(cardsEl);

        // password: client-side suffix match (k-anonymity finish)
        var pwEl = document.getElementById('ox-password-result');
        if (check.type === 'password') {
            var pwn = (check.sources || []).filter(function (x) { return x.key === 'pwnedpasswords'; })[0];
            if (pwn && pwn.data && pwn.data.suffixes) {
                var lines = String(pwn.data.suffixes).split('\n'), found = null;
                for (var i = 0; i < lines.length; i++) {
                    var p = lines[i].split(':');
                    if (p[0] && (pwn.data.range + p[0]) === fullHash) { found = parseInt(p[1], 10) || 0; break; }
                }
                pwEl.innerHTML = found === null
                    ? '<b>Password check complete</b><p style="color:var(--muted);font-size:12.5px;margin:6px 0 0">The database range was fetched and matched locally in your browser. No match could be confirmed for this exact password hash.</p>'
                    : (found === 0
                        ? '<b style="color:var(--green)">Good news — no exact match</b><p style="color:var(--muted);font-size:12.5px;margin:6px 0 0">This password was not found in the breach corpora indexed by HIBP Pwned Passwords. Still avoid reuse — one breach tomorrow changes this verdict.</p>'
                        : '<b style="color:var(--red)">This password is burned</b><p style="color:var(--muted);font-size:12.5px;margin:6px 0 0">It appears <strong>' + found.toLocaleString() + ' times</strong> in known breach corpora. Change it everywhere you used it — and never reuse it again.</p>');
                pwEl.hidden = false;
            }
        } else { pwEl.hidden = true; }
    }

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        errEl.hidden = true;
        var val = input.value.trim();
        if (!val) { errEl.textContent = 'Please enter an email, username, phone number, IP or password first.'; errEl.hidden = false; return; }
        goBtn.disabled = true; goBtn.textContent = 'Checking…';
        var ready;
        if (type === 'password') {
            ready = sha1Hex(val).then(function (h) { fullHash = h; return { type: 'password', prefix: h.substring(0, 5) }; });
        } else {
            fullHash = '';
            ready = Promise.resolve({ type: type, q: val });
        }
        ready.then(function (payload) {
            return fetch('{{ route('api.check') }}', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-TOKEN': document.querySelector('meta[name=csrf-token]').content, 'X-Requested-With': 'XMLHttpRequest' },
                credentials: 'same-origin',
                body: JSON.stringify(payload)
            });
        }).then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); })
        .then(function (res) {
            goBtn.disabled = false; goBtn.textContent = 'Check exposure →';
            var j = res.body || {};
            updateQuota(j.quota || (j.check && j.check.quota));
            if (!j.ok) { errEl.textContent = j.error || 'Check failed — please retry.'; errEl.hidden = false; resultsEl.hidden = true; return; }
            renderResult(j.check);
        }).catch(function (err) {
            goBtn.disabled = false; goBtn.textContent = 'Check exposure →';
            errEl.textContent = (err && err.message) ? err.message : 'Network error — please retry.';
            errEl.hidden = false;
        });
    });
})();
</script>
<style>
    .ox-tab { background:#16233F; color:#94A6C8; border:1px solid #22314F; border-radius:9px; padding:7px 14px; font-weight:700; font-size:12.5px; cursor:pointer; transition:all .15s; }
    .ox-tab:hover { color:#E5EDFF; border-color:#3B82F6; }
    .ox-tab.active { background:rgba(34,211,238,.14); color:#22D3EE; border-color:#22D3EE; }
    .ox-sec-head { display:flex; align-items:center; justify-content:space-between; gap:10px; flex-wrap:wrap; margin:18px 0 10px; padding-bottom:8px; border-bottom:1px solid #1A2743; }
    .ox-sec-head.mt { margin-top:30px; }
    .ox-sec { display:grid; gap:10px; }
    .ox-card { background:#111C33; border:1px solid #1A2743; border-radius:12px; padding:14px 16px; animation: oxin .4s ease both; }
    @keyframes oxin { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:none; } }
    .ox-head { display:flex; gap:12px; align-items:flex-start; cursor:default; }
    .ox-src-logo { flex:0 0 auto; }
    .ox-head-main { flex:1; min-width:0; }
    .ox-title { font-weight:800; font-size:13.5px; display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    .ox-summary { color:#94A6C8; font-size:12.5px; margin-top:3px; }
    .ox-head-side { flex:0 0 auto; }
    .ox-body { display:grid; grid-template-columns:repeat(auto-fill,minmax(210px,1fr)); gap:6px 18px; margin-top:12px; padding-top:10px; border-top:1px dashed #1A2743; }
    .ox-kv { font-size:12px; color:#94A6C8; overflow:hidden; text-overflow:ellipsis; }
    .ox-kv span { color:#64748B; margin-right:6px; }
    .ox-kv b { color:#E5EDFF; font-weight:700; }
    .ox-tile { width:30px; height:30px; border-radius:8px; display:inline-flex; align-items:center; justify-content:center; font-weight:800; font-size:13px; }
    .ox-accounts { display:flex; gap:8px; flex-wrap:wrap; margin-top:12px; }
    .ox-acct { display:flex; flex-direction:column; align-items:center; gap:5px; width:74px; padding:9px 4px; background:#16233F; border:1px solid #22314F; border-radius:10px; color:#94A6C8; font-size:10.5px; font-weight:700; text-align:center; transition:border-color .15s, transform .15s; }
    .ox-acct:hover { border-color:#22D3EE; color:#E5EDFF; text-decoration:none; transform:translateY(-2px); }
    .ox-acct img, .ox-tile { width:30px; height:30px; object-fit:contain; border-radius:7px; background:#0F172A; }
    .ox-acct span { max-width:70px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .ox-acct.more { justify-content:center; font-size:11px; }
    .ox-acct { position:relative; }
    .ox-conf { position:absolute; top:4px; right:6px; font-style:normal; font-size:10px; font-weight:800; line-height:1; pointer-events:none; }
    .ox-conf.conf-c { color:#34D399; }
    .ox-conf.conf-p { color:#FBBF24; }
    .ox-conf-line { color:#64748B; font-size:11px; margin-top:8px; }
</style>
@endpush
