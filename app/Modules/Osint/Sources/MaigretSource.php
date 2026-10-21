<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use App\Modules\Osint\OsintLogoService;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Storage;

/**
 * MaigretSource — username footprint across 150 differential-verified popular sites
 * (2MNY Trace / Exposure Check; 43 maigret sites 2026-10-16 + 107 WhatsMyName sites 2026-10-20, both differential-verified from production egress).
 * =============================================================================
 *
 * DATA: curated subset of maigret's MIT-licensed site database
 * (https://github.com/soxoj/maigret — v0.6.6 data.json, 2026-10-10).
 * 43 globally-recognizable, username-based sites (social, dev, content,
 * commerce). Differential self-check from the production egress IP
 * (2026-10-16): 41/43 PASS claimed-vs-unclaimed; dropped: bot-walled
 * (Facebook, Pinterest, TikTok, Amazon), datacenter-403 (Twitter/X, Vimeo,
 * Etsy, Ebay...), broken probes. Vendored at storage/app/maigret/sites.json.
 *
 * CHECK LOGIC (faithful to maigret's checking.py semantics):
 *   status_code  : probe URL -> 200 = account exists, 404 = free,
 *                  anything else = site unusable this run
 *   message      : errors dict first (any error string in body -> site
 *                  unavailable, with maigret's own reason text); then
 *                  claimed = (no absenceStr in body) AND (at least one
 *                  presenseStr in body, when defined)
 *   response_url : claimed when the probe redirects (final URL differs
 *                  from the probe URL); falls back to "unknown" when the
 *                  HTTP layer cannot expose the effective URI (honest,
 *                  never guessed)
 *
 * ETHICS (same rules as maigret): we report ONLY the existence of a
 * public profile and its public URL — data that is public by definition.
 * No avatars, bios, follower counts or any third-party personal data.
 * A wider username footprint is an exposure signal, scored modestly
 * (low severity 1-9 hits, medium 10+), never presented as a breach.
 *
 * FAILURE HONESTY: sites that answer with a bot challenge, rate-limit or
 * transport error are reported as unavailable (listed, not counted) —
 * they can NEVER turn a "no account found" into a clean verdict by
 * themselves: clean requires >=10 successfully assessed sites.
 */
class MaigretSource implements OsintSource
{
    private const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

    /** @var array<string, array>|null */
    private ?array $sitesCache = null;

    /** Minimum successfully-assessed sites before a "clean" verdict is honest. */
    private const MIN_ASSESSED_FOR_CLEAN = 10;

    public function key(): string
    {
        return 'maigret';
    }

    public function label(): string
    {
        $n = count($this->sites());
        return 'Social Account Footprint — ' . $n . ' popular sites (maigret + WhatsMyName DB)';
    }

    public function category(): string
    {
        return 'profile';
    }

    public function supports(string $type): bool
    {
        return $type === 'username';
    }

    /**
     * Vendored site DB (storage/app/maigret/sites.json, bind-mounted and
     * persistent). Falls back to an empty set -> source unavailable, never
     * a fake clean.
     * @return array<string, array>
     */
    private function sites(): array
    {
        if ($this->sitesCache !== null) {
            return $this->sitesCache;
        }
        try {
            $raw = Storage::disk('local')->get('maigret/sites.json');
            $doc = is_string($raw) ? json_decode($raw, true) : null;
            $this->sitesCache = is_array($doc) && isset($doc['sites']) && is_array($doc['sites'])
                ? $doc['sites']
                : [];
        } catch (\Throwable $e) {
            $this->sitesCache = [];
        }

        return $this->sitesCache;
    }

    /** Does the username satisfy a site's maigret regexCheck (when defined)? */
    private function usernameAllowed(array $site, string $username): bool
    {
        if (empty($site['regexCheck']) || !is_string($site['regexCheck'])) {
            return true;
        }
        $rx = str_replace('/', '\/', $site['regexCheck']);
        $ok = @preg_match('/' . $rx . '/', $username);
        if ($ok === false) {
            return true; // unparseable pattern -> do not silently skip the site
        }

        return $ok === 1;
    }

    public function requests(string $type, string $identifier): array
    {
        $specs = [];
        $i = 0;
        foreach ($this->sites() as $name => $site) {
            if (!$this->usernameAllowed($site, $identifier)) {
                continue;
            }
            $i++;
            $headers = ['user-agent' => self::UA];
            foreach (($site['headers'] ?? []) as $k => $v) {
                $headers[strtolower((string) $k)] = (string) $v;
            }
            $specs[] = [
                'name' => sprintf('%s.s%03d', $this->key(), $i),
                'method' => 'GET',
                'url' => str_replace('{username}', rawurlencode($identifier), (string) $site['urlProbe']),
                'headers' => $headers,
                '_site' => $name, // internal bookkeeping (stripped by the pool)
            ];
        }

        return $specs;
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $sites = $this->sites();
        if ($sites === []) {
            return ['status' => 'unavailable', 'summary' => 'Site database unavailable right now.', 'data' => []];
        }

        // Rebuild the same spec order to map response names back to sites.
        $ordered = [];
        $i = 0;
        foreach ($sites as $name => $site) {
            if (!$this->usernameAllowed($site, $identifier)) {
                continue;
            }
            $i++;
            $ordered[sprintf('%s.s%03d', $this->key(), $i)] = [$name, $site];
        }

        $found = [];
        $free = 0;
        $assessed = 0;
        $unavailable = [];
        $skipped = count($sites) - count($ordered);

        foreach ($ordered as $respName => [$name, $site]) {
            $resp = $responses[$respName] ?? null;
            if (!$resp instanceof Response) {
                $unavailable[$name] = 'no response';
                continue;
            }
            try {
                $verdict = $this->assess($resp, $site);
            } catch (\Throwable $e) {
                $verdict = ['state' => 'error', 'reason' => 'assessment failure'];
            }
            if ($verdict['state'] === 'claimed') {
                $assessed++;
                $found[] = ['site' => (string) ($site['name'] ?? $name), 'url' => str_replace('{username}', rawurlencode($identifier), (string) $site['url'])];
            } elseif ($verdict['state'] === 'free') {
                $assessed++;
                $free++;
            } else {
                $unavailable[$name] = $verdict['reason'] ?? 'unusable response';
            }
        }

        // sort found by popularity (rank asc)
        usort($found, function ($a, $b) use ($sites) {
            $ra = $sites[$a['site']]['rank'] ?? 999999;
            $rb = $sites[$b['site']]['rank'] ?? 999999;

            return $ra <=> $rb;
        });

        $n = count($found);

        // DISPLAY v2 (2026-10-17): accounts grid data for the frontend logo
        // grid (emailosint.org parity) + favicon registration so /osint-logo/{key}
        // can serve each platform's logo. Data-only change: verdicts untouched.
        $accounts = [];
        try {
            $logos = app(OsintLogoService::class);
            foreach ($found as $f) {
                $key = OsintLogoService::keyForSite((string) $f['site']);
                $domain = OsintLogoService::domainFromUrl((string) $f['url']);
                if ($domain !== null) {
                    $logos->registerSite($key, $domain);
                }
                $accounts[] = ['site' => (string) $f['site'], 'url' => (string) $f['url'], 'status' => 'found'];
            }
        } catch (\Throwable $e) {
            // logo registration is display sugar — never affects verdicts
        }

        $data = [
            'found_accounts' => $found,
            'profile_urls' => array_column($found, 'url'),
            'sites_in_db' => count($sites),
            'sites_checked' => $assessed,
            'sites_found' => $n,
            'sites_unavailable' => count($unavailable),
        ];
        if ($accounts !== []) {
            $data['accounts'] = $accounts;
        }
        if ($skipped > 0) {
            $data['sites_skipped_format'] = $skipped;
        }
        if ($unavailable !== []) {
            $data['unavailable_examples'] = array_slice($unavailable, 0, 5, true);
        }

        if ($n > 0) {
            $list = implode(', ', array_slice(array_column($found, 'site'), 0, 6));
            $more = $n > 6 ? sprintf(' (+%d more)', $n - 6) : '';
            return [
                'status' => 'hit',
                'severity' => $n >= 10 ? 'medium' : 'low',
                'summary' => sprintf(
                    'This username is registered on %d of %d assessed popular sites, including %s%s — each public account widens the identity footprint.',
                    $n, $assessed, $list, $more
                ),
                'data' => $data,
            ];
        }

        if ($assessed >= self::MIN_ASSESSED_FOR_CLEAN) {
            return [
                'status' => 'clean',
                'severity' => 'info',
                'summary' => sprintf(
                    'No public account found for this username on any of the %d popular sites that answered (%d did not answer reliably).',
                    $assessed, count($unavailable)
                ),
                'data' => $data,
            ];
        }

        return [
            'status' => 'unavailable',
            'summary' => sprintf(
                'Too few sites answered reliably this run (%d of %d) — result withheld rather than guessed.',
                $assessed, count($sites)
            ),
            'data' => $data,
        ];
    }

    /**
     * Apply maigret's per-site check semantics to one response.
     * Logic validated 2026-10-16 by differential self-check (claimed vs
     * unclaimed usernames) from the production egress IP: 41/43 sites pass.
     * @return array{state: 'claimed'|'free'|'error', reason?: string}
     */
    private function assess(Response $resp, array $site): array
    {
        $status = $resp->status();
        $type = (string) ($site['checkType'] ?? 'status_code');

        // Transport-level failures = site unusable, never "free".
        if ($status === 0 || $status >= 500 || $status === 429) {
            return ['state' => 'error', 'reason' => $status === 429 ? 'rate limited' : 'server error ' . $status];
        }

        // A plain 404/410 on a profile probe means the account does not
        // exist — for ALL check types (YouTube message probes 404, many
        // status_code probes 404). Checked BEFORE the errors-dict scan so
        // a 404 challenge page can never masquerade as a message verdict.
        if ($status === 404 || $status === 410) {
            return ['state' => 'free'];
        }

        // Sites whose API answers 400 for FREE usernames (e.g. Bluesky
        // getProfile: "Could not find handle") — never an error there.
        if ($status === 400 && !empty($site['treat400Free'])) {
            return ['state' => 'free'];
        }

        if ($type === 'status_code') {
            if ($status >= 200 && $status < 300) {
                return ['state' => 'claimed'];
            }

            return ['state' => 'error', 'reason' => 'unexpected status ' . $status];
        }

        if ($type === 'response_url') {
            try {
                $final = $resp->effectiveUri();
                $probe = (string) $site['urlProbe'];
                if ($final instanceof \GuzzleHttp\Psr7\Uri && (string) $final !== $probe) {
                    return ['state' => 'claimed'];
                }
                if ($status >= 200 && $status < 300 && (string) $final === $probe) {
                    return ['state' => 'claimed']; // landed on the profile itself
                }

                return ['state' => 'error', 'reason' => 'indeterminate redirect'];
            } catch (\Throwable $e) {
                return ['state' => 'error', 'reason' => 'redirect info unavailable'];
            }
        }

        // message check
        $body = (string) $resp->body();
        if (strlen($body) === 0) {
            return ['state' => 'error', 'reason' => 'empty body'];
        }
        foreach (($site['errors'] ?? []) as $needle => $reason) {
            if (str_contains($body, (string) $needle)) {
                return ['state' => 'error', 'reason' => (string) $reason];
            }
        }
        if ($status !== 200) {
            return ['state' => 'error', 'reason' => 'status ' . $status];
        }
        foreach (($site['absenceStrs'] ?? []) as $needle) {
            if (str_contains($body, (string) $needle)) {
                return ['state' => 'free'];
            }
        }
        $presence = $site['presenseStrs'] ?? [];
        if ($presence === []) {
            return ['state' => 'claimed']; // only absence strings defined and none matched
        }
        foreach ($presence as $needle) {
            if (str_contains($body, (string) $needle)) {
                return ['state' => 'claimed'];
            }
        }

        return ['state' => 'free'];
    }
}
