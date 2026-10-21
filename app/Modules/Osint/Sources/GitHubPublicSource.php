<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * GitHub Public Activity (free API; optional server PAT deepens limits) —
 * "where is this email / username used publicly" signal, 1 request per
 * check. Complements the consent-gated holehe linked-account scan with a
 * zero-contact lookup that never touches the platforms themselves.
 *
 *   email   → search/commits author-email:{email}
 *             (the address was used to author PUBLIC commits — visible to
 *              anyone, harvestable, and proves a GitHub-registered identity)
 *   username→ search/users q={username}, exact login match only
 *   domain  → search/commits author-email:@{domain}
 *             (organization emails exposed in public code)
 *
 * Rate care: search API = 30 req/min with the server token, 10/min without.
 * The check endpoint already bursts at 10/min per IP, so we never exceed
 * budget. 403/429 or transport failure degrades to honest 'unavailable'.
 *
 * Ethics: public API metadata only — repo names, dates, counts. Commit
 * content is never fetched. Domain results mask every address (j***n@d).
 */
class GitHubPublicSource implements OsintSource
{
    private const API = 'https://api.github.com';

    public function key(): string
    {
        return 'github_public';
    }

    public function label(): string
    {
        return 'GitHub Public Activity';
    }

    public function category(): string
    {
        return 'profile';
    }

    public function supports(string $type): bool
    {
        return in_array($type, ['email', 'username', 'domain'], true);
    }

    public function requests(string $type, string $identifier): array
    {
        if ($type === 'email') {
            $url = self::API . '/search/commits?q=' . rawurlencode('author-email:' . $identifier) . '&per_page=5&sort=author-date';
        } elseif ($type === 'domain') {
            $url = self::API . '/search/commits?q=' . rawurlencode('author-email:@' . $identifier) . '&per_page=30&sort=author-date';
        } elseif ($type === 'username') {
            $url = self::API . '/search/users?q=' . rawurlencode($identifier . ' in:login') . '&per_page=10';
        } else {
            return [];
        }

        return [
            [
                'name' => $this->key() . '.main',
                'method' => 'GET',
                'url' => $url,
                'headers' => $this->headers(),
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $resp = $responses[$this->key() . '.main'] ?? null;
        if (!$resp instanceof Response || !$resp->ok()) {
            $code = $resp instanceof Response ? $resp->status() : 0;
            $msg = in_array($code, [403, 429], true)
                ? 'GitHub API rate budget is spent right now — try again in a minute.'
                : 'GitHub public-activity lookup unavailable right now.';

            return ['status' => 'unavailable', 'summary' => $msg, 'data' => []];
        }

        $json = $resp->json();
        $items = is_array($json) && is_array($json['items'] ?? null) ? $json['items'] : [];
        $total = is_array($json) ? (int) ($json['total_count'] ?? 0) : 0;

        if ($type === 'email') {
            return $this->parseEmail($identifier, $total, $items);
        }
        if ($type === 'domain') {
            return $this->parseDomain($identifier, $total, $items);
        }
        if ($type === 'username') {
            return $this->parseUsername($identifier, $total, $items);
        }

        return ['status' => 'unavailable', 'summary' => 'Unsupported check type.', 'data' => []];
    }

    // ── parsers ─────────────────────────────────────────────────────

    /**
     * @param array<int,mixed> $items
     * @return array<string,mixed>
     */
    private function parseEmail(string $email, int $total, array $items): array
    {
        if ($total <= 0 || $items === []) {
            return [
                'status' => 'clean',
                'summary' => 'No public GitHub commits authored with this email address.',
                'severity' => 'info',
                'data' => ['commits' => 0, 'note' => 'The address does not appear as a commit author in public repositories.'],
            ];
        }

        $repos = [];
        $last = '';
        foreach ($items as $it) {
            if (!is_array($it)) {
                continue;
            }
            $repo = (string) ($it['repository']['full_name'] ?? '');
            if ($repo !== '' && !in_array($repo, $repos, true) && count($repos) < 3) {
                $repos[] = $repo;
            }
            $d = (string) ($it['commit']['author']['date'] ?? '');
            if ($d > $last) {
                $last = $d;
            }
        }

        return [
            'status' => 'hit',
            'summary' => 'FOUND — this email authored ' . $this->num($total) . ' public GitHub commit' . ($total === 1 ? '' : 's') . '. The address is publicly harvestable and tied to a GitHub identity.',
            'severity' => 'low',
            'data' => [
                'commits' => $total,
                'repositories' => $repos,
                'latest_commit' => $last !== '' ? substr($last, 0, 10) : '',
                'note' => 'Developers often forget every public commit exposes their email. Use GitHub\'s noreply address (Settings → Emails → keep email private) to stop future exposure.',
            ],
        ];
    }

    /**
     * @param array<int,mixed> $items
     * @return array<string,mixed>
     */
    private function parseDomain(string $domain, int $total, array $items): array
    {
        if ($total <= 0 || $items === []) {
            return [
                'status' => 'clean',
                'summary' => 'No public GitHub commits authored from this domain\'s addresses.',
                'severity' => 'info',
                'data' => ['commits' => 0],
            ];
        }

        $emails = [];
        $repos = [];
        foreach ($items as $it) {
            if (!is_array($it)) {
                continue;
            }
            // GitHub commit author emails are often malformed (spaces before
            // the @, empty local parts — verified live on the gmail.com
            // corpus). Strip all whitespace, then keep well-formed only.
            $e = str_replace(' ', '', strtolower((string) ($it['commit']['author']['email'] ?? '')));
            if ($e !== '' && str_ends_with($e, '@' . strtolower($domain))
                && preg_match('/^[a-z0-9._%+\-]{1,64}@' . preg_quote(strtolower($domain), '/') . '$/', $e)) {
                $emails[$e] = true;
            }
            $repo = (string) ($it['repository']['full_name'] ?? '');
            if ($repo !== '' && !in_array($repo, $repos, true) && count($repos) < 3) {
                $repos[] = $repo;
            }
        }

        // Commits matched the query but none carried a well-formed org
        // address (author emails are junk strings) — nothing harvestable
        // to report, stay honest instead of claiming "0 addresses found".
        if ($emails === []) {
            return [
                'status' => 'clean',
                'summary' => 'No well-formed ' . $domain . ' addresses found in public GitHub commit authors.',
                'severity' => 'info',
                'data' => [
                    'commits_matched' => $total,
                    'note' => 'The search matched ' . $this->num($total) . ' commit(s), but their author-email fields are malformed (not real organizational addresses) — nothing harvestable.',
                ],
            ];
        }

        $masked = array_map(fn (string $e) => $this->maskEmail($e), array_slice(array_keys($emails), 0, 8));

        return [
            'status' => 'hit',
            'summary' => 'FOUND — ' . $this->num($total) . ' public GitHub commits authored by ' . count($emails) . ' address(es) at this domain. Those addresses are publicly harvestable.',
            'severity' => 'medium',
            'data' => [
                'commits' => $total,
                'emails_found' => count($emails),
                'masked_emails' => $masked,
                'repositories' => $repos,
                'note' => 'Public commit history exposes organizational email addresses to spammers and phishers. Developers should switch to the GitHub noreply address.',
            ],
        ];
    }

    /**
     * @param array<int,mixed> $items
     * @return array<string,mixed>
     */
    private function parseUsername(string $username, int $total, array $items): array
    {
        $low = strtolower($username);
        $match = null;
        foreach ($items as $it) {
            if (is_array($it) && strtolower((string) ($it['login'] ?? '')) === $low) {
                $match = $it;
                break;
            }
        }

        if ($match === null) {
            return [
                'status' => 'clean',
                'summary' => 'No GitHub account with this exact username.',
                'severity' => 'info',
                'data' => ['account' => 0, 'note' => 'No exact-login match in public GitHub accounts.'],
            ];
        }

        $url = (string) ($match['html_url'] ?? ('https://github.com/' . $match['login']));

        return [
            'status' => 'hit',
            'summary' => 'FOUND — a GitHub account exists with this exact username.',
            'severity' => 'low',
            'data' => [
                'account' => 1,
                'profile' => $url,
                'account_type' => (string) ($match['type'] ?? 'User'),
                'note' => 'The account is public — anyone can view its activity, repos and join date.',
            ],
        ];
    }

    // ── helpers ─────────────────────────────────────────────────────

    /** @return array<string,string> */
    private function headers(): array
    {
        $h = [
            'Accept' => 'application/vnd.github+json',
            'User-Agent' => '2mny-trace/1.0 (+https://2mny.com/exposure-check)',
        ];
        $token = $this->token();
        if ($token !== '') {
            $h['Authorization'] = 'Bearer ' . $token;
        }

        return $h;
    }

    /** Server PAT (optional) — same discovery order as GitHubRepoService. */
    private function token(): string
    {
        if (!empty($_ENV['GITHUB_API_TOKEN'])) {
            return (string) $_ENV['GITHUB_API_TOKEN'];
        }
        if (!empty($_SERVER['GITHUB_API_TOKEN'])) {
            return (string) $_SERVER['GITHUB_API_TOKEN'];
        }
        $v = getenv('GITHUB_API_TOKEN');

        return ($v === false || $v === '') ? '' : (string) $v;
    }

    private function maskEmail(string $email): string
    {
        $at = strrpos($email, '@');
        if ($at === false || $at === 0) {
            return $email;
        }
        $local = substr($email, 0, $at);

        return mb_substr($local, 0, 1) . '***' . (mb_strlen($local) > 2 ? mb_substr($local, -1, 1) : '') . substr($email, $at);
    }

    private function num(int $n): string
    {
        return $n >= 1000 ? '1,000+' : (string) $n;
    }
}
