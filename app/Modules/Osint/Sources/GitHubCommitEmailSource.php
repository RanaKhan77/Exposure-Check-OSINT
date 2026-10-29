<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

use Illuminate\Http\Client\Response;

/**
 * GitHub commit author-email pivot (v1.7.0, W58 OSINT adoption research).
 * ============================================================
 *
 * GET https://api.github.com/search/commits?q=author:{username}&per_page=100&sort=author-date
 *
 * The reverse of the existing github_public email check: given a GitHub
 * USERNAME, which email addresses did this account author public commits
 * with? Countless developers push with their real personal or corporate
 * address instead of GitHub's noreply — the address is then harvestable
 * from any public .patch URL. This card makes that exposure visible to the
 * account owner in one lookup.
 *
 * Found in the W58 OSINT repo deep-pass; adopted on dual independent model
 * reviews with an explicit caveat that shaped this implementation:
 * PROBABLE tier — git author fields are freely spoofable (anyone can write
 * any email into a commit), and GitHub associates commits to accounts via
 * the email-to-account mapping. A match is therefore evidence, not proof;
 * the card says so, and addresses are MASKED (j***n@gmail.com) to keep the
 * tool an exposure checker rather than a harvester.
 *
 * ZERO-MATCH SEMANTICS (live-verified 2026-10-29 from the production egress):
 * an author:{username} qualifier-only query that MATCHES returns 200
 * (author:torvalds, author:octocat); a qualifier-only query with ZERO
 * matches returns 422 "Validation Failed — Search text is required…".
 * author-email:{...} queries instead return 200/total_count=0 on zero
 * matches. For a username we already format-validated, 422 therefore
 * means "no public commits associated to this login" — reported CLEAN,
 * never unavailable.
 *
 * Rate care: same unauthenticated search budget as github_public (10/min
 * per IP; optional server PAT raises it). 403/429 degrade honestly.
 *
 * HONESTY RULES:
 *  - total_count 0 -> clean (account authored no public commits, or none
 *    are associated to this login).
 *  - Commits matched but every author-email field is malformed/empty ->
 *    clean with an honest note (nothing harvestable), never a fake hit.
 *  - Only @users.noreply.github.com addresses -> clean: the account uses
 *    GitHub's privacy-protecting addresses — good hygiene, say so.
 *  - Real addresses -> hit (medium): masked list + probable caveat.
 */
class GitHubCommitEmailSource implements OsintSource
{
    private const API = 'https://api.github.com';

    public function key(): string
    {
        return 'github_commit_email';
    }

    public function label(): string
    {
        return 'GitHub Commit Author Emails';
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
        $user = strtolower(trim($identifier));
        if ($user === '' || strlen($user) > 39 || !preg_match('/^[a-z0-9-]+$/', $user)) {
            return [];
        }

        return [
            [
                'name' => $this->key() . '.main',
                'method' => 'GET',
                'url' => self::API . '/search/commits?q=' . rawurlencode('author:' . $user) . '&per_page=100&sort=author-date',
                'headers' => $this->headers(),
            ],
        ];
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $resp = $responses[$this->key() . '.main'] ?? null;
        if (!$resp instanceof Response || !$resp->ok()) {
            $code = $resp instanceof Response ? $resp->status() : 0;
            if ($code === 422 && $resp instanceof Response) {
                // Qualifier-only commit search with ZERO matches (empirical
                // GitHub semantics, see class docblock) — but ONLY when the
                // error body is the documented "Search text is required /
                // qualifiers only" validation message. Any other 422 is an
                // unknown upstream state -> honest unavailable, never clean.
                $body = (string) $resp->body();
                if (str_contains($body, 'Search text is required') || str_contains($body, 'qualifiers only')) {
                    return [
                        'status' => 'clean',
                        'severity' => 'info',
                        'summary' => 'No public GitHub commits authored by this account.',
                        'data' => [
                            'commits' => 0,
                            'note' => 'Either the account has no public activity or its commits are not associated to this login.',
                        ],
                    ];
                }
                return ['status' => 'unavailable', 'summary' => 'GitHub commit-email lookup unavailable right now.', 'data' => []];
            }
            $msg = in_array($code, [403, 429], true)
                ? 'GitHub API rate budget is spent right now — try again in a minute.'
                : 'GitHub commit-email lookup unavailable right now.';

            return ['status' => 'unavailable', 'summary' => $msg, 'data' => []];
        }

        $json = $resp->json();
        $items = is_array($json) && is_array($json['items'] ?? null) ? $json['items'] : [];
        $total = is_array($json) ? (int) ($json['total_count'] ?? 0) : 0;

        if ($total <= 0 || $items === []) {
            return [
                'status' => 'clean',
                'severity' => 'info',
                'summary' => 'No public GitHub commits authored by this account.',
                'data' => [
                    'commits' => 0,
                    'note' => 'Either the account has no public activity or its commits are not associated to this login.',
                ],
            ];
        }

        // ── collect author emails (normalize like github_public: strip
        //    whitespace, lowercase, keep well-formed only) ──────────────
        $emails = [];
        $repos = [];
        $last = '';
        foreach ($items as $it) {
            if (!is_array($it)) {
                continue;
            }
            $e = str_replace(' ', '', strtolower((string) ($it['commit']['author']['email'] ?? '')));
            if ($e !== '' && preg_match('/^[a-z0-9._%+\-]{1,64}@[a-z0-9.+\-]+\.[a-z]{2,}$/', $e)) {
                $emails[$e] = true;
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

        if ($emails === []) {
            return [
                'status' => 'clean',
                'severity' => 'info',
                'summary' => 'Commits found, but none carry a well-formed author email.',
                'data' => [
                    'commits_matched' => $total,
                    'note' => 'The search matched ' . $total . ' commit(s) but their author-email fields are malformed — nothing harvestable.',
                ],
            ];
        }

        $real = [];
        $noreply = [];
        foreach (array_keys($emails) as $e) {
            // Both noreply shapes: the modern @users.noreply.github.com and
            // the legacy {user}@noreply.github.com — either is privacy-safe.
            if (str_ends_with($e, '@users.noreply.github.com') || str_ends_with($e, '@noreply.github.com')) {
                $noreply[] = $e;
            } else {
                $real[] = $e;
            }
        }

        if ($real === []) {
            return [
                'status' => 'clean',
                'severity' => 'info',
                'summary' => 'Good hygiene — every public commit uses GitHub\'s noreply address; no real email exposed.',
                'data' => [
                    'commits' => $total,
                    'real_emails' => 0,
                    'noreply_only' => true,
                    'repositories' => $repos,
                    'note' => 'This account authors commits with @users.noreply.github.com addresses, so spammers cannot harvest a real address from its history. Keep it that way (Settings → Emails → Keep my email addresses private).',
                ],
            ];
        }

        $masked = array_map(fn (string $e) => $this->maskEmail($e), array_slice($real, 0, 8));

        return [
            'status' => 'hit',
            'severity' => 'medium',
            'summary' => 'FOUND — ' . $this->num($total) . ' public commits by this account expose ' . count($real) . ' real email address(es) as git author fields (probable, not proven — git author fields are spoofable).',
            'data' => [
                'commits' => $total,
                'real_emails' => count($real),
                'masked_emails' => $masked,
                'noreply_emails' => count($noreply),
                'repositories' => $repos,
                'latest_commit' => $last !== '' ? substr($last, 0, 10) : '',
                'note' => 'Sampled from the latest ' . count($items) . ' matching commits (GitHub search caps one page). Developers frequently push with a personal or corporate address instead of GitHub\'s noreply one; the address is then harvestable from any public .patch URL. Switch to the noreply address (Settings → Emails) for future commits. Caveat: git author fields can be set to any value, so treat matches as probable evidence of exposure, not cryptographic proof.',
            ],
        ];
    }

    // ── helpers (same conventions as GitHubPublicSource) ──────────────

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

    /** Server PAT (optional) — same discovery order as GitHubPublicSource. */
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
