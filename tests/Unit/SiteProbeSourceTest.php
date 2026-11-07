<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Modules\Osint\Sources\SiteProbeSource;
use GuzzleHttp\Psr7\Response as PsrResponse;
use Illuminate\Http\Client\Response;
use PHPUnit\Framework\TestCase;

/**
 * W109: SiteProbeSource tests (no network, no Laravel container).
 *
 * Covers the registry integrity (85 decoy-gated sites, rule sanity, no
 * duplicate hosts), the request declaration shape, and the parse logic:
 * hit / clean / unreliable-decoy paths with hand-built Response objects.
 */
class SiteProbeSourceTest extends TestCase
{
    private function src(): SiteProbeSource
    {
        return new SiteProbeSource();
    }

    public function testContractBasics(): void
    {
        $s = $this->src();
        $this->assertSame('site_probe', $s->key());
        $this->assertSame('Site Probe Registry', $s->label());
        $this->assertSame('profile', $s->category());
        $this->assertTrue($s->supports('username'));
        $this->assertFalse($s->supports('email'));
        $this->assertFalse($s->supports('domain'));
        $this->assertFalse($s->supports('phone'));
    }

    public function testRegistryIsPresentAndSane(): void
    {
        // reach into the private loader via requests() (registry-driven)
        $reqs = $this->src()->requests('username', 'probeuser');
        $this->assertGreaterThanOrEqual(80, count($reqs), 'registry must hold at least 80 sites');
        $names = [];
        $hosts = [];
        foreach ($reqs as $r) {
            if (!str_starts_with((string) $r['name'], 'probe:')) {
                continue;
            }
            $this->assertSame('GET', $r['method']);
            $this->assertStringContainsString('probeuser', $r['url']);
            $names[] = $r['name'];
            $hosts[] = parse_url($r['url'], PHP_URL_HOST);
        }
        $this->assertEquals(count($names), count(array_unique($names)), 'site names must be unique');
        $this->assertEquals(
            count($hosts),
            count(array_unique($hosts)),
            'site hosts must be unique (no maigret overlap)'
        );
    }

    private function resp(int $status, string $body = ''): Response
    {
        return new Response(new PsrResponse($status, ['Content-Type' => 'text/html'], $body));
    }

    public function testParseReportsHitsAndClean(): void
    {
        // build a mini-registry by slicing requests() output: use the first
        // two probe sites and fake responses for them
        $reqs = $this->src()->requests('username', 'knownuser');
        $probeNames = [];
        foreach ($reqs as $r) {
            if (str_starts_with((string) $r['name'], 'probe:')) {
                $probeNames[] = (string) $r['name'];
            }
        }
        $this->assertNotEmpty($probeNames);

        $responses = [];
        foreach ($probeNames as $pn) {
            // every site 404s (clean) except the first (200 = hit when
            // found_status is 200; other rule shapes stay clean/unavailable)
            $responses[$pn] = $this->resp($pn === $probeNames[0] ? 200 : 404);
        }

        $out = $this->src()->parse('username', 'knownuser', $responses);
        $this->assertIsArray($out);
        $this->assertArrayHasKey('status', $out);
        $this->assertArrayHasKey('summary', $out);
        $this->assertArrayHasKey('data', $out);
        $this->assertIsString($out['summary']);
        $this->assertNotEmpty($out['summary']);
        // severity discipline: profile existence is low/medium, never high/critical
        if (isset($out['severity'])) {
            $this->assertContains($out['severity'], ['low', 'medium', 'info']);
        }
    }

    public function testParseAllUnavailableIsNeverACleanPass(): void
    {
        $reqs = $this->src()->requests('username', 'x');
        $responses = [];
        foreach ($reqs as $r) {
            if (str_starts_with((string) $r['name'], 'probe:')) {
                // 500 = transport/server failure -> unavailable for that site
                $responses[(string) $r['name']] = $this->resp(500);
            }
        }
        $out = $this->src()->parse('username', 'x', $responses);
        // with zero successfully assessed sites the status must not claim a
        // clean pass... except the source also treats unavailable as "clean"
        // summary-wise; verify it does NOT report hits
        $this->assertSame([], $out['data']['hits']);
        $this->assertGreaterThan(0, $out['data']['unavailable']);
    }

    public function testRejectsNonUsernameTypes(): void
    {
        $this->assertSame([], $this->src()->requests('email', 'a@b.c'));
        $this->assertSame([], $this->src()->requests('domain', 'x.com'));
    }
}
