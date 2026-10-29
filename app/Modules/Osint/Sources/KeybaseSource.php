<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * Keybase public lookup (v1.7.0, W58 OSINT adoption research) — keyless.
 * ============================================================
 *
 * GET https://keybase.io/_/api/1.0/user/lookup.json?username={user}
 *   -> {"status":{"code":0,"name":"OK"},"them":{...}}   account exists
 *   -> {"status":{"code":205,"name":"NOT_FOUND"},"them":null}
 *   -> {"status":{"code":100,"name":"INPUT_ERROR"},...} malformed username
 *      (live-verified 2026-10-29: >20-char names; digit-start IS allowed)
 *
 * Keybase is an identity layer: users deliberately publish verifiable
 * PROOFS linking one username to their Twitter, GitHub, Reddit, HackerNews,
 * DNS domains, websites and crypto keys. For a personal exposure check this
 * answers a question no other source can: "if I have a Keybase account,
 * how much of my identity graph does one username unlock?"
 *
 * Found in the W58 OSINT repo deep-pass (dual independent model reviews,
 * both models ADOPT): keyless, official public API, one request, clean
 * 205-for-missing semantics — the cleanest identity-graph pivot available.
 *
 * Response shape (live-verified 2026-10-29): proofs live in
 * them.proofs_summary.all[] = {proof_type, nametag, state, service_url, ...}
 * with state=1 for verified proofs; the older by_type field comes back null
 * and is only used as a fallback.
 *
 * HONESTY RULES:
 *  - status.code 205 -> clean (verified no-account).
 *  - code 100 / other non-zero codes, 429, 5xx, transport failure -> honest
 *    'unavailable'. A failed lookup is NEVER reported as "no account".
 *  - Only VERIFIED proofs (state=1) count; unverified claims are ignored.
 *  - Proofs shown are the account owner's deliberately-public claims
 *    (that is Keybase's purpose) — no third-party data is returned.
 */
class KeybaseSource implements OsintSource
{
    private const URL = 'https://keybase.io/_/api/1.0/user/lookup.json?username=';

    public function key(): string
    {
        return 'keybase';
    }

    public function label(): string
    {
        return 'Keybase — Linked Identities';
    }

    public function category(): string
    {
        return 'profile';
    }

    public function supports(string $type): bool
    {
        return $type === 'username';
    }

    public function requests(string $type, string $identifier): array
    {
        // Keybase username rules (live-verified): 1-20 chars, [a-z0-9_],
        // digits allowed at the start. Anything else is INPUT_ERROR at the
        // API — skip the request entirely instead of wasting one.
        $user = strtolower(trim($identifier));
        if ($user === '' || strlen($user) > 20 || !preg_match('/^[a-z0-9_]+$/', $user)) {
            return [];
        }

        return [
            [
                'name' => $this->key() . '.main',
                'method' => 'GET',
                'url' => self::URL . urlencode($user),
                'headers' => ['Accept' => 'application/json'],
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $resp = $responses[$this->key() . '.main'] ?? null;
        if (!$resp instanceof Response) {
            return ['status' => 'unavailable', 'summary' => 'Keybase lookup unavailable right now.', 'data' => []];
        }

        $code = $resp->status();
        // 429 (rate-limited) and 5xx are honest unavailables; the API's own
        // error codes arrive with HTTP 200 and are decoded below.
        if ($code === 429 || $code >= 500) {
            return ['status' => 'unavailable', 'summary' => 'Keybase lookup unavailable right now.', 'data' => []];
        }

        $j = $resp->json();
        if (!is_array($j)) {
            return ['status' => 'unavailable', 'summary' => 'Keybase lookup unavailable right now.', 'data' => []];
        }

        $status = is_array($j['status'] ?? null) ? $j['status'] : [];
        $apiCode = (int) ($status['code'] ?? -1);
        $them = $j['them'] ?? null;

        // Documented missing-user: code 205 (live-verified).
        if ($apiCode === 205) {
            return [
                'status' => 'clean',
                'severity' => 'info',
                'summary' => 'No Keybase account with this username.',
                'data' => ['exists' => false],
            ];
        }

        if ($apiCode !== 0 || !is_array($them)) {
            // 100 INPUT_ERROR for a format we already validated, or any
            // other upstream state — ambiguous, never fake a clean.
            return ['status' => 'unavailable', 'summary' => 'Keybase lookup unavailable right now.', 'data' => []];
        }

        return $this->parseAccount($them);
    }

    /**
     * @param array<string,mixed> $them
     * @return array<string,mixed>
     */
    private function parseAccount(array $them): array
    {
        $username = (string) ($them['basics']['username'] ?? '');
        $ctime = (int) ($them['basics']['ctime'] ?? 0);
        $since = $ctime > 0 ? gmdate('Y', $ctime) : '';

        $fullName = trim((string) ($them['profile']['full_name'] ?? ''));
        $location = trim((string) ($them['profile']['location'] ?? ''));

        // Verified proofs only, from proofs_summary.all[]
        // ({proof_type, nametag, state}); the legacy by_type field returns
        // null in current responses and carries no state flag, so it is
        // deliberately NOT used — an unfilterable claim list would break
        // the verified-only rule (dual-AI review 2026-10-29).
        $proofs = [];
        $seen = [];
        $all = $them['proofs_summary']['all'] ?? null;
        if (is_array($all)) {
            foreach ($all as $p) {
                if (!is_array($p) || (int) ($p['state'] ?? 0) !== 1) {
                    continue;
                }
                $ptype = strtolower((string) ($p['proof_type'] ?? ''));
                $pid = trim((string) ($p['nametag'] ?? ''));
                if ($ptype === '' || $pid === '') {
                    continue;
                }
                $dedup = $ptype . ':' . strtolower($pid);
                if (isset($seen[$dedup])) {
                    continue;
                }
                $seen[$dedup] = true;
                $proofs[] = ['type' => $ptype, 'id' => mb_substr($pid, 0, 80)];
                if (count($proofs) >= 12) {
                    break;
                }
            }
        }

        $fingerprint = '';
        $pk = $them['public_keys']['primary'] ?? null;
        if (is_array($pk)) {
            $fingerprint = (string) ($pk['fingerprint'] ?? '');
        }

        $data = [
            'exists' => true,
            'username' => $username !== '' ? $username : 'keybase account',
            'member_since' => $since,
            'linked_identities' => $proofs,
            'links_count' => count($proofs),
            'pgp_fingerprint' => $fingerprint !== '' ? $fingerprint : '',
        ];
        if ($fullName !== '') {
            $data['display_name'] = $fullName;
        }
        if ($location !== '') {
            $data['location'] = $location;
        }

        $labels = [];
        foreach (array_slice($proofs, 0, 4) as $p) {
            $labels[] = $p['type'];
        }
        $more = count($proofs) - count($labels);
        $linkPart = $proofs === []
            ? 'no verified linked identities published'
            : 'publicly links ' . count($proofs) . ' identit' . (count($proofs) === 1 ? 'y' : 'ies') . ' (' . implode(', ', $labels) . ($more > 0 ? ', +' . $more . ' more' : '') . ')';

        // Identity-graph semantics: a bare account is a low-severity
        // footprint; 3+ verified links (e.g. twitter + github + dns)
        // is a real deanonymization pivot — medium.
        $severity = count($proofs) >= 3 ? 'medium' : 'low';

        return [
            'status' => 'hit',
            'severity' => $severity,
            'summary' => sprintf(
                'FOUND — Keybase account%s exists and %s. Proofs are deliberately public: one username unlocks the rest of the identity graph.',
                $since !== '' ? ' (member since ' . $since . ')' : '',
                $linkPart
            ),
            'data' => $data,
        ];
    }
}
