<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Modules\Osint\OsintCheckService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

/**
 * v1.1 ec:doctor — the install self-test command.
 * Pins: command registers + runs, JSON shape, exit code semantics, and the
 * source reachability matrix (registry-derived count) (with faked network so CI stays hermetic).
 */
class DoctorCommandTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        config(['app.admin_password' => 'doctor-test']);
    }

    public function test_doctor_is_registered_and_reports_healthy_install_as_json(): void
    {
        Http::fake(['*' => Http::response('ok', 200)]);

        $exit = Artisan::call('ec:doctor', ['--json' => true]);
        $this->assertSame(0, $exit, 'healthy install must exit 0');

        $out = json_decode(Artisan::output(), true);
        $this->assertIsArray($out);
        $this->assertTrue($out['ok']);
        $this->assertSame(0, $out['failed']);
        $this->assertGreaterThan(0, $out['passed']);
        $this->assertNotEmpty($out['checks']);

        // every shipped source was probed; probed ones saw a response, local
        // data sources (no HTTP request, e.g. the disposable blocklist) WARN
        // honestly with 'no probe request declared' — never 'unreachable'.
        $this->assertCount(count(OsintCheckService::SOURCES), $out['sources']);
        $passes = 0;
        foreach ($out['sources'] as $probe) {
            $this->assertNotSame('FAIL', $probe['status']);
            $this->assertStringNotContainsString('unreachable', $probe['detail']);
            if ($probe['status'] === 'PASS') {
                $passes++;
                $this->assertSame(200, $probe['http']);
            }
        }
        $this->assertGreaterThanOrEqual(15, $passes, 'most sources should be reachable under Http::fake');

        // the config-level checks that must PASS in the test environment
        $byName = collect($out['checks'])->keyBy('name');
        $this->assertSame('PASS', $byName['PHP version']['status']);
        $this->assertSame('PASS', $byName['PHP extensions']['status']);
        $this->assertSame('PASS', $byName['App key']['status']);
        $this->assertSame('PASS', $byName['Admin password']['status']);
        $this->assertSame('PASS', $byName['Maigret site database']['status']);
    }

    public function test_doctor_warns_not_fails_when_a_source_is_unreachable(): void
    {
        // Everything times out (transport failure) — that is a WARN, never a FAIL.
        Http::fake(function () {
            throw new \Illuminate\Http\Client\ConnectionException('connection refused');
        });

        $exit = Artisan::call('ec:doctor', ['--json' => true]);
        $this->assertSame(0, $exit, 'unreachable sources alone must not fail the doctor');

        $out = json_decode(Artisan::output(), true);
        $this->assertTrue($out['ok']);
        $this->assertGreaterThan(0, $out['warned']);
        foreach ($out['sources'] as $probe) {
            $this->assertSame('WARN', $probe['status']);
        }
    }

    public function test_doctor_fails_when_app_key_is_missing(): void
    {
        config(['app.key' => null]);
        Http::fake(['*' => Http::response('ok', 200)]);

        $exit = Artisan::call('ec:doctor', ['--json' => true]);
        $this->assertSame(1, $exit, 'missing app key must FAIL the doctor');

        $out = json_decode(Artisan::output(), true);
        $this->assertFalse($out['ok']);
        $byName = collect($out['checks'])->keyBy('name');
        $this->assertSame('FAIL', $byName['App key']['status']);
    }
}
