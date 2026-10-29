<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Modules\Osint\Sources\DnsblSource;
use PHPUnit\Framework\TestCase;

/**
 * DnsblSource tests (v1.6.0, W58 OSINT adoption research — DNS blocklist
 * reputation for IPv4).
 *
 * Network-free tests only: the live DNS query path (dns_get_record) is
 * exercised by manual/live verification, not by unit tests. What we pin
 * down here is the contract and the honest-degradation paths that do not
 * need DNS.
 */
final class DnsblSourceTest extends TestCase
{
    private DnsblSource $src;

    protected function setUp(): void
    {
        $this->src = new DnsblSource();
    }

    public function test_supports_ip_only(): void
    {
        $this->assertTrue($this->src->supports('ip'));
        foreach (['email', 'username', 'phone', 'password', 'domain'] as $t) {
            $this->assertFalse($this->src->supports($t), "must not support {$t}");
        }
    }

    public function test_identity_fields(): void
    {
        $this->assertSame('dnsbl', $this->src->key());
        $this->assertMatchesRegularExpression('/^[a-z][a-z0-9_]*$/', $this->src->key());
        $this->assertSame('reputation', $this->src->category());
        $this->assertNotSame('', $this->src->label());
    }

    public function test_no_http_requests_ever(): void
    {
        $this->assertSame([], $this->src->requests('ip', '8.8.8.8'));
    }

    public function test_ipv6_not_assessed_honestly(): void
    {
        $r = $this->src->parse('ip', '2001:db8::1', []);
        $this->assertSame('unavailable', $r['status']);
        $this->assertStringContainsStringIgnoringCase('IPv4', $r['summary'] . json_encode($r['data']));
    }

    public function test_garbage_input_not_assessed(): void
    {
        $r = $this->src->parse('ip', 'not-an-ip', []);
        $this->assertSame('unavailable', $r['status']);
    }

    public function test_result_shape_when_no_dns_available(): void
    {
        // A valid IPv4 that cannot be resolved in this environment still
        // yields a well-formed result with the three contract keys — the
        // status may be clean or unavailable depending on the resolver,
        // but the shape must never break.
        $r = $this->src->parse('ip', '192.0.2.123', []);
        $this->assertContains($r['status'], ['hit', 'clean', 'unavailable']);
        $this->assertArrayHasKey('summary', $r);
        $this->assertArrayHasKey('data', $r);
        $this->assertIsArray($r['data']);
    }
}
