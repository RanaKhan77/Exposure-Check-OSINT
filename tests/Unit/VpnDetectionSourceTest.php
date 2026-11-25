<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Modules\Osint\Sources\VpnDetectionSource;
use GuzzleHttp\Psr7\Response as Psr7Response;
use Illuminate\Http\Client\Response;
use PHPUnit\Framework\TestCase;

/**
 * VpnDetectionSource tests: the contract, the flag mapping on answers shaped like
 * api.vpndetection.io's, and the honest-degradation paths. Network-free.
 */
final class VpnDetectionSourceTest extends TestCase
{
    private VpnDetectionSource $src;

    protected function setUp(): void
    {
        $this->src = new VpnDetectionSource();
    }

    private function answer(array $body, int $status = 200): array
    {
        $json = json_encode($body);
        return ['vpndetection.main' => new Response(new Psr7Response($status, ['Content-Type' => 'application/json'], $json))];
    }

    private function body(bool $vpn, bool $tor, bool $relay, string $asnType): array
    {
        return [
            'ip' => '146.70.116.130', 'is_bogon' => false, 'is_vpn' => $vpn, 'is_relay' => $relay, 'is_tor' => $tor,
            'location' => ['country' => 'AT'],
            'asn' => ['asn' => 9009, 'name' => 'M247 Europe SRL', 'type' => $asnType],
        ];
    }

    public function testSupportsIpOnly(): void
    {
        $this->assertTrue($this->src->supports('ip'));
        foreach (['email', 'username', 'phone', 'password', 'domain'] as $t) {
            $this->assertFalse($this->src->supports($t), "must not support {$t}");
        }
        $this->assertSame('vpndetection', $this->src->key());
        $this->assertSame('reputation', $this->src->category());
    }

    public function testRequestsTheAddressKeyless(): void
    {
        $req = $this->src->requests('ip', '2001:db8::1');
        $this->assertCount(1, $req);
        $this->assertSame('https://api.vpndetection.io/2001%3Adb8%3A%3A1', $req[0]['url']);
        $this->assertArrayNotHasKey('Authorization', $req[0]['headers']);
    }

    public function testVpnOnAHostingNetworkIsAMediumHit(): void
    {
        $r = $this->src->parse('ip', '146.70.116.130', $this->answer($this->body(true, false, false, 'hosting')));
        $this->assertSame('hit', $r['status']);
        $this->assertSame('medium', $r['severity']);
        $this->assertStringContainsString('vpn, datacenter', $r['summary']);
        $this->assertSame('AS9009', $r['data']['asn']);
        $this->assertSame('M247 Europe SRL', $r['data']['company']);
        $this->assertSame('AT', $r['data']['country']);
    }

    public function testRelayAloneIsALowHit(): void
    {
        $r = $this->src->parse('ip', '172.224.226.1', $this->answer($this->body(false, false, true, 'isp')));
        $this->assertSame('hit', $r['status']);
        $this->assertSame('low', $r['severity']);
        $this->assertTrue($r['data']['relay']);
    }

    public function testResidentialIsClean(): void
    {
        $r = $this->src->parse('ip', '81.2.69.142', $this->answer($this->body(false, false, false, 'isp')));
        $this->assertSame('clean', $r['status']);
        $this->assertSame('info', $r['severity']);
    }

    public function testFailuresAreUnavailableNeverClean(): void
    {
        $this->assertSame('unavailable', $this->src->parse('ip', '1.1.1.1', [])['status']);
        $this->assertSame('unavailable', $this->src->parse('ip', '1.1.1.1', $this->answer(['error' => 'x'], 429))['status']);
        $this->assertSame('unavailable', $this->src->parse('ip', '1.1.1.1', $this->answer(['error' => 'x']))['status']);
    }
}
