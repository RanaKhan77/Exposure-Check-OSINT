#!/usr/bin/env python3
"""EC v1.3.1: wire CrtShSource + RdapSource (mirror production) — service, controller, blade, tests, docs.
Runs ON SERVER in /tmp/ec-git."""
import re

def sub(path, pairs, allow_multi=False):
    s = open(path, encoding="utf-8").read()
    for old, new in pairs:
        assert old in s, f"ANCHOR MISSING in {path}: {old[:70]!r}"
        if not allow_multi:
            assert s.count(old) == 1, f"NOT UNIQUE in {path}: {old[:70]!r}"
        s = s.replace(old, new, 1 if not allow_multi else -1)
    open(path, "w", encoding="utf-8").write(s)
    print(f"ok {path}: {len(pairs)} edits")

# ---------- 1. OsintCheckService ----------
P = "app/Modules/Osint/OsintCheckService.php"
sub(P, [
    # imports (alphabetical: CrtSh after Bluesky, Rdap after ProxyNova)
    ("use App\\Modules\\Osint\\Sources\\BlueskySource;\nuse App\\Modules\\Osint\\Sources\\DisifySource;",
     "use App\\Modules\\Osint\\Sources\\BlueskySource;\nuse App\\Modules\\Osint\\Sources\\CrtShSource;\nuse App\\Modules\\Osint\\Sources\\DisifySource;"),
    ("use App\\Modules\\Osint\\Sources\\ProxyNovaCombSource;\nuse App\\Modules\\Osint\\Sources\\ShodanInternetDbSource;",
     "use App\\Modules\\Osint\\Sources\\ProxyNovaCombSource;\nuse App\\Modules\\Osint\\Sources\\RdapSource;\nuse App\\Modules\\Osint\\Sources\\ShodanInternetDbSource;"),
    # SOURCES: append the two domain-infra sources with the v1.3.0 comment
    ("        // v1.2.0 (2026-10-21, S32): offline bot-CIDR attribution (CrawlerScope-inspired)\n        BotCidrSource::class,\n    ];",
     "        // v1.2.0 (2026-10-21, S32): offline bot-CIDR attribution (CrawlerScope-inspired)\n        BotCidrSource::class,\n        // v1.3.0 (2026-10-22, gap-analysis D1): domain-infra sources, keyless\n        CrtShSource::class,\n        RdapSource::class,\n    ];"),
    # TYPES: add domain (production order)
    ("    public const TYPES = ['email', 'username', 'phone', 'password', 'ip'];",
     "    public const TYPES = ['email', 'username', 'phone', 'password', 'domain', 'ip'];"),
])

# docblock: update the CE-deltas note
s = open(P, encoding="utf-8").read()
old_doc = """ * Extracted from the 2MNY production engine (2026-10-21) with the CE deltas:
 *   - Check types: email | username | phone | password | ip.
 *     The 'domain' type is intentionally absent — that is the Website
 *     Vulnerability Scanner CE's job (see README, "Scope").
 *   - Keyless sources only. The owner-keyed source and the two domain/CT
 *     sources of the hosted product are NOT shipped here.
 *   - No Trace-Pro / billing logic anywhere in the CE."""
new_doc = """ * Extracted from the 2MNY production engine (2026-10-21) with the CE deltas:
 *   - Check types: email | username | phone | password | domain | ip.
 *     The 'domain' type (added v1.3.0) surfaces a domain's public
 *     infrastructure footprint only — CT-log subdomain history and
 *     registry data. Website vulnerability scanning stays in the
 *     Website Vulnerability Scanner CE.
 *   - Keyless sources only (21). The owner-keyed source of the hosted
 *     product is NOT shipped here.
 *   - No Trace-Pro / billing logic anywhere in the CE."""
assert old_doc in s, "docblock anchor missing"
s = s.replace(old_doc, new_doc, 1)
open(P, "w", encoding="utf-8").write(s)
print("ok docblock")

# normalize: add domain case (mirror production)
sub(P, [
    ("""            case 'password':
                // 5-char SHA-1 prefix ONLY (k-anonymity - never the password).
                return preg_match('/^[0-9A-Fa-f]{5}$/', $identifier) ? strtoupper($identifier) : '';
            case 'ip':""",
     """            case 'password':
                // 5-char SHA-1 prefix ONLY (k-anonymity - never the password).
                return preg_match('/^[0-9A-Fa-f]{5}$/', $identifier) ? strtoupper($identifier) : '';
            case 'domain':
                $identifier = strtolower(preg_replace('/^https?:\\/\\//', '', $identifier) ?? $identifier);
                $identifier = preg_replace('/\\/.*$/', '', $identifier) ?? $identifier;

                return filter_var($identifier, FILTER_VALIDATE_DOMAIN) ? $identifier : '';
            case 'ip':"""),
])

# mask: add domain case — check current mask shape first
s = open(P, encoding="utf-8").read()
m = re.search(r"case 'password':\n(.*?)case 'ip':", s, re.S)
assert m, "mask password->ip anchor missing"
mpw = m.group(1)
old_mask = "case 'password':\n" + mpw + "case 'ip':"
new_mask = "case 'password':\n" + mpw + "case 'domain':\n            case 'ip':"
assert s.count(old_mask) == 1
s = s.replace(old_mask, new_mask, 1)
open(P, "w", encoding="utf-8").write(s)
print("ok mask domain case")

# ---------- 2. SourceContractTest ----------
sub("tests/Unit/SourceContractTest.php", [
    ("""    public function test_check_types_do_not_include_domain(): void
    {
        // Scope rule: domain/website checks belong to the scanner CE.
        $this->assertNotContains('domain', OsintCheckService::TYPES);
        $this->assertSame(['email', 'username', 'phone', 'password', 'ip'], OsintCheckService::TYPES);
    }""",
     """    public function test_check_types_include_domain_infra(): void
    {
        // v1.3.0: the domain type surfaces a domain's public infrastructure
        // footprint (CT-log history, registry data) — the fraud/trust signal.
        // Website vulnerability scanning stays in the scanner CE.
        $this->assertSame(['email', 'username', 'phone', 'password', 'domain', 'ip'], OsintCheckService::TYPES);
    }"""),
])

# ---------- 3. DashboardController detectType ----------
sub("app/Http/Controllers/DashboardController.php", [
    ("""        if (preg_match('/^\\+?\\d[\\d\\s().-]{6,20}$/', $q)) {
            return 'phone';
        }

        return 'username';""",
     """        if (preg_match('/^\\+?\\d[\\d\\s().-]{6,20}$/', $q)) {
            return 'phone';
        }
        $stripped = strtolower((string) preg_replace('/^https?:\\/\\//', '', $q));
        $stripped = (string) preg_replace('/\\/.*$/', '', $stripped);
        if (str_contains($stripped, '.') && filter_var($stripped, FILTER_VALIDATE_DOMAIN)) {
            return 'domain';
        }

        return 'username';"""),
])

# ---------- 4. dashboard.blade.php ----------
sub("resources/views/dashboard.blade.php", [
    ('<button type="button" class="ox-tab" data-type="password">🔑 Password</button>',
     '<button type="button" class="ox-tab" data-type="password">🔑 Password</button>\n            <button type="button" class="ox-tab" data-type="domain">🗺️ Domain</button>'),
    ("""        password: 'type a password — hashed in your browser, never sent',
        ip: '8.8.8.8 or 2606:4700::1111'
    };""",
     """        password: 'type a password — hashed in your browser, never sent',
        domain: 'example.com — public TLS & registry footprint',
        ip: '8.8.8.8 or 2606:4700::1111'
    };"""),
    ("""        if (/^\\+?\\d[\\d\\s().-]{6,20}$/.test(q)) return 'phone';
        return 'username';""",
     """        if (/^\\+?\\d[\\d\\s().-]{6,20}$/.test(q)) return 'phone';
        var d = q.replace(/^https?:\\/\\//i, '').replace(/\\/.*$/, '').toLowerCase();
        if (d.indexOf('.') !== -1 && /^[a-z0-9-]+(\\.[a-z0-9-]+)+$/.test(d)) return 'domain';
        return 'username';"""),
    ("<p class=\"sub\">Check if an email, username, phone number, password or IP is exposed",
     "<p class=\"sub\">Check if an email, username, phone number, password, domain or IP is exposed"),
])
print("ALL WIRING DONE")
