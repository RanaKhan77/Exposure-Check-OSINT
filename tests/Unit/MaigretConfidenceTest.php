<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Modules\Osint\Sources\MaigretSource;
use GuzzleHttp\Psr7\Response as Psr7Response;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

/**
 * v1.1 username confidence tiers: body-verified hits are 'confirmed',
 * bare status-code matches are 'probable'. The tier is derived from the
 * site's checkType (maigret semantics) and flows into found_accounts,
 * the accounts grid payload and the summary sentence.
 */
class MaigretConfidenceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Storage::fake('local');
        Storage::disk('local')->put('maigret/sites.json', (string) json_encode([
            'sites' => [
                'BodySite' => [
                    'name' => 'BodySite', 'rank' => 1,
                    'url' => 'https://body.example/u/{username}',
                    'urlProbe' => 'https://body.example/u/{username}',
                    'checkType' => 'message',
                    'presenseStrs' => ['PROFILE_FOUND'],
                    'absenceStrs' => ['no such user'],
                ],
                'CodeSite' => [
                    'name' => 'CodeSite', 'rank' => 2,
                    'url' => 'https://code.example/u/{username}',
                    'urlProbe' => 'https://code.example/u/{username}',
                    'checkType' => 'status_code',
                ],
                'AwaySite' => [
                    'name' => 'AwaySite', 'rank' => 3,
                    'url' => 'https://away.example/u/{username}',
                    'urlProbe' => 'https://away.example/u/{username}',
                    'checkType' => 'message',
                    'presenseStrs' => ['PROFILE_FOUND'],
                    'absenceStrs' => ['no such user'],
                ],
            ],
        ]));
    }

    private function resp(int $status, string $body): Response
    {
        return new Response(new Psr7Response($status, [], $body));
    }

    public function test_hits_are_tiered_confirmed_vs_probable(): void
    {
        $src = new MaigretSource();
        $reqs = $src->requests('username', 'doctor');
        $this->assertCount(3, $reqs);

        $responses = [
            $reqs[0]['name'] => $this->resp(200, 'Welcome — PROFILE_FOUND'), // BodySite: message hit
            $reqs[1]['name'] => $this->resp(200, 'anything'),                // CodeSite: status-only hit
            $reqs[2]['name'] => $this->resp(200, 'sorry, no such user'),     // AwaySite: free
        ];

        $r = $src->parse('username', 'doctor', $responses);

        $this->assertSame('hit', $r['status']);
        $d = $r['data'];
        $this->assertSame(2, $d['sites_found']);
        $this->assertSame(1, $d['found_confirmed']);
        $this->assertSame(1, $d['found_probable']);

        // rank order preserved: BodySite (1) before CodeSite (2)
        $this->assertSame('BodySite', $d['found_accounts'][0]['site']);
        $this->assertSame('confirmed', $d['found_accounts'][0]['confidence']);
        $this->assertSame('CodeSite', $d['found_accounts'][1]['site']);
        $this->assertSame('probable', $d['found_accounts'][1]['confidence']);

        // accounts grid payload carries the tier too
        $this->assertSame('confirmed', $d['accounts'][0]['confidence']);
        $this->assertSame('probable', $d['accounts'][1]['confidence']);

        // the human summary explains the tiers
        $this->assertStringContainsString('1 confirmed by page content', (string) $r['summary']);
        $this->assertStringContainsString('1 probable by status code alone', (string) $r['summary']);
    }

    public function test_clean_verdict_has_zero_confidence_counts(): void
    {
        // MIN_ASSESSED_FOR_CLEAN is 10 — build 12 sites so 'clean' is honest.
        $sites = [];
        for ($i = 1; $i <= 12; $i++) {
            $sites['Site' . $i] = [
                'name' => 'Site' . $i, 'rank' => $i,
                'url' => 'https://s' . $i . '.example/u/{username}',
                'urlProbe' => 'https://s' . $i . '.example/u/{username}',
                'checkType' => 'message',
                'presenseStrs' => ['PROFILE_FOUND'],
                'absenceStrs' => ['no such user'],
            ];
        }
        Storage::disk('local')->put('maigret/sites.json', (string) json_encode(['sites' => $sites]));

        $src = new MaigretSource();
        $reqs = $src->requests('username', 'ghostuser');
        $this->assertCount(12, $reqs);

        $responses = [];
        foreach ($reqs as $i => $req) {
            $responses[$req['name']] = $this->resp($i === 0 ? 404 : 200, $i === 0 ? 'gone' : 'no such user');
        }

        $r = $src->parse('username', 'ghostuser', $responses);
        $this->assertSame('clean', $r['status']); // 12 assessed >= MIN_ASSESSED_FOR_CLEAN (10)
        $this->assertSame(0, $r['data']['found_confirmed']);
        $this->assertSame(0, $r['data']['found_probable']);
        $this->assertStringContainsString('No public account found', (string) $r['summary']);
    }

    public function test_unavailable_sites_never_become_hits(): void
    {
        $src = new MaigretSource();
        $reqs = $src->requests('username', 'doctor');

        $responses = [
            $reqs[0]['name'] => $this->resp(503, 'down'),        // BodySite: error
            $reqs[1]['name'] => $this->resp(429, 'slow down'),   // CodeSite: error
            $reqs[2]['name'] => $this->resp(200, 'no such user'),// AwaySite: free
        ];

        $r = $src->parse('username', 'doctor', $responses);
        // only 1 site assessed < MIN_ASSESSED_FOR_CLEAN(10) -> honest unavailable
        $this->assertSame('unavailable', $r['status']);
        $this->assertSame(0, $r['data']['sites_found']);
    }
}
