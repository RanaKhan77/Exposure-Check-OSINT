<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Modules\Osint\OsintCheckService;
use App\Modules\Osint\Sources\OsintSource;
use App\Services\SettingsService;
use PHPUnit\Framework\TestCase;

/**
 * Contract tests: every shipped source must satisfy the OsintSource
 * interface cleanly (keys, labels, categories, support matrix, request
 * specs well-formed). These run without network access and without the
 * Laravel container — sources are deliberately constructor-free.
 */
class SourceContractTest extends TestCase
{
    /** @return array<int, OsintSource> */
    private function sources(): array
    {
        $out = [];
        foreach (OsintCheckService::SOURCES as $cls) {
            $out[] = new $cls();
        }

        return $out;
    }

    private function service(): OsintCheckService
    {
        return new OsintCheckService(new SettingsService());
    }

    public function test_every_source_implements_the_interface(): void
    {
        foreach (OsintCheckService::SOURCES as $cls) {
            $this->assertContains(OsintSource::class, class_implements($cls), "$cls must implement OsintSource");
        }
        $this->assertNotEmpty(OsintCheckService::SOURCES);
    }

    public function test_source_keys_are_unique_snake_case(): void
    {
        $keys = [];
        foreach ($this->sources() as $src) {
            $key = $src->key();
            $this->assertMatchesRegularExpression('/^[a-z][a-z0-9_]*$/', $key, get_class($src) . ' key must be snake_case');
            $keys[] = $key;
        }
        $this->assertCount(count(array_unique($keys)), $keys, 'source keys must be unique');
    }

    public function test_categories_are_known(): void
    {
        $valid = ['stealer', 'breach', 'reputation', 'profile', 'email', 'infra'];
        foreach ($this->sources() as $src) {
            $cat = $src->category();
            $this->assertContains($cat, $valid, get_class($src) . " category '$cat' must be a known card category");
        }
    }

    public function test_check_types_do_not_include_domain(): void
    {
        // Scope rule: domain/website checks belong to the scanner CE.
        $this->assertNotContains('domain', OsintCheckService::TYPES);
        $this->assertSame(['email', 'username', 'phone', 'password', 'ip'], OsintCheckService::TYPES);
    }

    public function test_support_matrix_has_coverage_for_every_type(): void
    {
        $byType = array_fill_keys(OsintCheckService::TYPES, 0);
        foreach ($this->sources() as $src) {
            foreach (OsintCheckService::TYPES as $t) {
                if ($src->supports($t)) {
                    $byType[$t]++;
                }
            }
        }
        foreach ($byType as $type => $n) {
            $this->assertGreaterThan(0, $n, "type '$type' must be supported by at least one source");
        }
    }

    public function test_request_specs_are_well_formed_for_sample_identifiers(): void
    {
        $samples = [
            'email' => 'test@example.com',
            'username' => 'testuser',
            'phone' => '8801712345678',
            // k-anonymity: 5-hex prefix only, never the password
            'password' => '21BD1',
            'ip' => '8.8.8.8',
        ];
        foreach ($this->sources() as $src) {
            foreach ($samples as $type => $identifier) {
                if (!$src->supports($type)) {
                    continue;
                }
                foreach ($src->requests($type, $identifier) as $req) {
                    $this->assertIsArray($req);
                    $this->assertArrayHasKey('name', $req);
                    $this->assertArrayHasKey('method', $req);
                    $this->assertArrayHasKey('url', $req);
                    $this->assertStringStartsWith('https://', $req['url'], get_class($src) . ' must use HTTPS');
                }
            }
        }
    }

    public function test_normalize_validates_inputs(): void
    {
        $svc = $this->service();
        $this->assertSame('', $svc->normalize('email', 'not-an-email'));
        $this->assertSame('a@b.co', $svc->normalize('email', ' A@B.CO '));
        $this->assertSame('', $svc->normalize('username', 'x'));
        $this->assertSame('8801712345678', $svc->normalize('phone', '+880 171-234 5678'));
        // password: only a 5-hex prefix is ever accepted (k-anonymity)
        $this->assertSame('21BD1', $svc->normalize('password', '21bd1'));
        $this->assertSame('', $svc->normalize('password', str_repeat('A', 40)));
        $this->assertSame('8.8.8.8', $svc->normalize('ip', '8.8.8.8'));
        $this->assertSame('', $svc->normalize('ip', '999.999.999.999'));
    }

    public function test_masking_never_reveals_full_identifier(): void
    {
        $svc = $this->service();
        $this->assertSame('j***e@gmail.com', $svc->mask('email', 'johndoe@gmail.com'));
        $this->assertStringNotContainsString('johndoe', $svc->mask('email', 'johndoe@gmail.com'));
        $this->assertStringNotContainsString('1234', $svc->mask('phone', '8801712345678'));
        $this->assertStringStartsWith('SHA-1', $svc->mask('password', '21BD1'));
    }

    public function test_sanitize_for_storage_strips_credential_lines(): void
    {
        $svc = $this->service();
        $payload = [
            'sources' => [
                ['key' => 'x', 'data' => ['credential_lines' => ['user:pass'], 'hits' => 3]],
                ['key' => 'y', 'data' => ['other' => 'kept']],
            ],
        ];
        $out = $svc->sanitizeForStorage($payload);
        $this->assertArrayNotHasKey('credential_lines', $out['sources'][0]['data']);
        $this->assertSame(3, $out['sources'][0]['data']['hits']);
        $this->assertSame('kept', $out['sources'][1]['data']['other']);
    }
}
