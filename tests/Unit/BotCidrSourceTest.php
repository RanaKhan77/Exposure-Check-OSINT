<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Modules\Osint\Sources\BotCidrSource;
use PHPUnit\Framework\TestCase;

/**
 * BotCidrSource tests (v1.2.0, S32 — offline bot-CIDR attribution).
 */
final class BotCidrSourceTest extends TestCase
{
    private BotCidrSource $src;

    protected function setUp(): void
    {
        $this->src = new BotCidrSource();
    }

    public function test_supports_ip_only(): void
    {
        $this->assertTrue($this->src->supports('ip'));
        $this->assertFalse($this->src->supports('email'));
        $this->assertFalse($this->src->supports('username'));
    }

    public function test_makes_zero_http_requests(): void
    {
        $this->assertSame([], $this->src->requests('ip', '66.249.66.1'));
    }

    public function test_googlebot_range_is_a_hit(): void
    {
        $r = $this->src->parse('ip', '66.249.66.1', []);
        $this->assertSame('hit', $r['status']);
        $this->assertSame('info', $r['severity']);
        $this->assertStringContainsString('Google', $r['summary']);
        $this->assertSame('66.249.64.0/19', $r['data']['Published range']);
    }

    public function test_bingbot_range_is_a_hit(): void
    {
        $r = $this->src->parse('ip', '157.55.39.7', []);
        $this->assertSame('hit', $r['status']);
        $this->assertStringContainsString('Bingbot', $r['summary']);
    }

    public function test_outside_all_ranges_is_clean_with_spoof_warning(): void
    {
        $r = $this->src->parse('ip', '203.0.113.10', []);
        $this->assertSame('clean', $r['status']);
        $this->assertStringContainsString('SPOOFED', $r['data']['What it means']);
    }

    public function test_boundary_ip_outside_prefix_is_clean(): void
    {
        // 66.249.64.0/19 ends at 66.249.95.255
        $r = $this->src->parse('ip', '66.249.96.1', []);
        $this->assertSame('clean', $r['status']);
    }

    public function test_ipv6_is_honest_unavailable(): void
    {
        $r = $this->src->parse('ip', '2620:11c:f008::108', []);
        $this->assertSame('unavailable', $r['status']);
    }

    public function test_malformed_ip_is_honest_unavailable(): void
    {
        $r = $this->src->parse('ip', 'not-an-ip', []);
        $this->assertSame('unavailable', $r['status']);
    }

    public function test_meta_and_apple_ranges(): void
    {
        $this->assertSame('hit', $this->src->parse('ip', '69.171.230.5', [])['status']);
        $this->assertSame('hit', $this->src->parse('ip', '17.249.32.10', [])['status']);
    }
}
