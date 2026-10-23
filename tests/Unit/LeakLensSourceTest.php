<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Modules\Osint\Sources\LeakLensSource;
use GuzzleHttp\Psr7\Response as Psr7Response;
use Illuminate\Http\Client\Response;
use PHPUnit\Framework\TestCase;

/**
 * LeakLensSource tests (v1.4.0, s33 P0 — breach-registry phone/username search).
 *
 * All responses are mocked (no network): the MCP envelope wraps a JSON text
 * payload exactly like the live endpoint.
 */
final class LeakLensSourceTest extends TestCase
{
    private LeakLensSource $src;

    protected function setUp(): void
    {
        $this->src = new LeakLensSource();
    }

    /** Build a mocked pool Response carrying an MCP envelope. */
    private function mcp(array $inner, bool $isError = false, int $status = 200): Response
    {
        $envelope = [
            'jsonrpc' => '2.0',
            'id' => 1,
            'result' => [
                'content' => [
                    ['type' => 'text', 'text' => json_encode($inner, JSON_UNESCAPED_SLASHES)],
                ],
                'isError' => $isError,
            ],
        ];

        return new Response(new Psr7Response($status, ['Content-Type' => 'application/json'], json_encode($envelope)));
    }

    private function responses(Response $resp): array
    {
        return ['leaklens.main' => $resp];
    }

    public function test_supports_phone_and_username_only(): void
    {
        $this->assertTrue($this->src->supports('phone'));
        $this->assertTrue($this->src->supports('username'));
        // email is covered by XposedOrNot direct; password by HIBP direct;
        // domain stays out of EC scope (scanner CE owns it)
        $this->assertFalse($this->src->supports('email'));
        $this->assertFalse($this->src->supports('password'));
        $this->assertFalse($this->src->supports('domain'));
        $this->assertFalse($this->src->supports('ip'));
    }

    public function test_request_is_a_valid_stateless_mcp_call(): void
    {
        $specs = $this->src->requests('phone', '8801712345678');
        $this->assertCount(1, $specs);
        $s = $specs[0];
        $this->assertSame('POST', $s['method']);
        $this->assertSame('https://leaklens.org/api/mcp', $s['url']);
        $this->assertSame('application/json', $s['headers']['Content-Type']);
        $body = json_decode((string) $s['body'], true);
        $this->assertSame('2.0', $body['jsonrpc']);
        $this->assertSame('tools/call', $body['method']);
        $this->assertSame('search_phone', $body['params']['name']);
        // international format per their tool contract
        $this->assertSame('+8801712345678', $body['params']['arguments']['phone']);
    }

    public function test_username_request_uses_search_username_tool(): void
    {
        $body = json_decode((string) $this->src->requests('username', 'someuser')[0]['body'], true);
        $this->assertSame('search_username', $body['params']['name']);
        $this->assertSame('someuser', $body['params']['arguments']['username']);
    }

    public function test_hit_exposes_aggregates_and_drops_credential_fields(): void
    {
        $inner = [
            'isExposed' => true,
            'exposedCount' => 2,
            'results' => [
                ['breach' => 'Collection1', 'date' => '2019-01-07', 'records' => 772904991, 'email' => 'victim@example.com', 'password' => 'hunter2'],
                ['source' => 'MyFitnessPal', 'year' => '2018'],
            ],
            'degraded' => true,
            'errors' => ['occrp-aleph'],
        ];
        $r = $this->src->parse('username', 'someuser', $this->responses($this->mcp($inner)));
        $this->assertSame('hit', $r['status']);
        $this->assertSame('high', $r['severity']);
        $this->assertSame(2, $r['data']['exposures']);
        $this->assertSame('Collection1 — 2019-01-07 — 772,904,991 records', $r['data']['records'][0]);
        $this->assertSame('MyFitnessPal — 2018', $r['data']['records'][1]);
        $this->assertStringContainsString('occrp-aleph', (string) $r['data']['degraded_upstreams']);
        // ethics: no credential or third-party identity fields survive
        $flat = json_encode($r['data']);
        $this->assertStringNotContainsString('victim@example.com', $flat);
        $this->assertStringNotContainsString('hunter2', $flat);
    }

    public function test_string_results_become_labels(): void
    {
        $inner = ['isExposed' => true, 'exposedCount' => 2, 'results' => ['BreachA', 'BreachB'], 'degraded' => false];
        $r = $this->src->parse('phone', '8801712345678', $this->responses($this->mcp($inner)));
        $this->assertSame('hit', $r['status']);
        $this->assertSame(['BreachA', 'BreachB'], $r['data']['records']);
    }

    public function test_clean_when_not_exposed_and_not_degraded(): void
    {
        $inner = ['isExposed' => false, 'exposedCount' => 0, 'results' => [], 'degraded' => false];
        $r = $this->src->parse('phone', '8801712345678', $this->responses($this->mcp($inner)));
        $this->assertSame('clean', $r['status']);
        $this->assertSame(0, $r['data']['exposures']);
    }

    public function test_degraded_clean_is_unavailable_never_fake_clean(): void
    {
        // the core honesty rule: upstreams errored, so "not found" is not trustworthy
        $inner = ['isExposed' => false, 'exposedCount' => 0, 'results' => [], 'degraded' => true, 'errors' => ['leakcheck', 'xposedornot']];
        $r = $this->src->parse('username', 'someuser', $this->responses($this->mcp($inner)));
        $this->assertSame('unavailable', $r['status']);
        $this->assertStringContainsString('leakcheck', $r['summary']);
    }

    public function test_mcp_isError_is_unavailable(): void
    {
        $r = $this->src->parse('username', 'someuser', $this->responses($this->mcp(['whatever' => 1], true)));
        $this->assertSame('unavailable', $r['status']);
    }

    public function test_transport_error_is_unavailable(): void
    {
        $r = $this->src->parse('username', 'someuser', []);
        $this->assertSame('unavailable', $r['status']);

        $http500 = new Response(new Psr7Response(500, [], 'boom'));
        $r = $this->src->parse('username', 'someuser', $this->responses($http500));
        $this->assertSame('unavailable', $r['status']);
    }

    public function test_malformed_envelope_is_unavailable(): void
    {
        $garbage = new Response(new Psr7Response(200, ['Content-Type' => 'application/json'], 'not json'));
        $r = $this->src->parse('username', 'someuser', $this->responses($garbage));
        $this->assertSame('unavailable', $r['status']);

        $noText = new Response(new Psr7Response(200, ['Content-Type' => 'application/json'], json_encode(['result' => ['content' => []]])));
        $r = $this->src->parse('username', 'someuser', $this->responses($noText));
        $this->assertSame('unavailable', $r['status']);
    }

    public function test_records_cap_at_ten(): void
    {
        $results = [];
        for ($i = 1; $i <= 25; $i++) {
            $results[] = ['breach' => 'B' . $i];
        }
        $inner = ['isExposed' => true, 'exposedCount' => 25, 'results' => $results, 'degraded' => false];
        $r = $this->src->parse('username', 'someuser', $this->responses($this->mcp($inner)));
        $this->assertSame('hit', $r['status']);
        $this->assertCount(10, $r['data']['records']);
        // the true count is still shown
        $this->assertSame(25, $r['data']['exposures']);
    }
}
