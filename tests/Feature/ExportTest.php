<?php

declare(strict_types=1);

namespace Tests\Feature;

use App\Models\ExposureCheck;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/**
 * v1.1 export endpoints: JSON + CSV downloads of stored checks.
 * Pins: auth gate, privacy (masked identifiers, credential re-strip),
 * correct headers, one-row-per-source CSV shape, password-check honesty.
 */
class ExportTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        config(['app.admin_password' => 'test-password-123']);
    }

    private function makeCheck(): ExposureCheck
    {
        return ExposureCheck::create([
            'type' => 'username',
            'identifier_hash' => str_repeat('a', 64),
            'identifier_masked' => 'doc***',
            'total_sources' => 3,
            'hits' => 1,
            'exposure_score' => 88,
            'results' => [
                [
                    'key' => 'maigret', 'label' => 'Social Account Footprint — 150 popular sites',
                    'category' => 'profile', 'status' => 'hit', 'severity' => 'low',
                    'summary' => 'registered on 2 of 3 assessed popular sites',
                    'data' => [
                        'found_accounts' => [
                            ['site' => 'GitHub', 'url' => 'https://github.com/doctor', 'confidence' => 'confirmed'],
                            ['site' => 'ExampleSite', 'url' => 'https://example.org/doctor', 'confidence' => 'probable'],
                        ],
                        'found_confirmed' => 1,
                        'found_probable' => 1,
                    ],
                ],
                [
                    'key' => 'xposedornot', 'label' => 'XposedOrNot', 'category' => 'breach',
                    'status' => 'clean', 'severity' => 'info',
                    'summary' => 'not found in tracked breaches', 'data' => [],
                ],
                [
                    'key' => 'proxynova', 'label' => 'ProxyNova COMB', 'category' => 'breach',
                    'status' => 'hit', 'severity' => 'high',
                    'summary' => 'found in COMB corpus',
                    // belt-and-braces: this must NEVER reach an export
                    'data' => ['credential_lines' => ['doctor:hunter2'], 'corpus' => 'comb'],
                ],
            ],
        ]);
    }

    public function test_exports_require_admin_session(): void
    {
        $check = $this->makeCheck();
        $this->get(route('report.export', [$check, 'json']))->assertRedirect(route('login'));
        $this->get(route('report.export', [$check, 'csv']))->assertRedirect(route('login'));
    }

    public function test_json_export_downloads_full_structure_without_credentials(): void
    {
        $check = $this->makeCheck();
        $this->post('/login', ['password' => 'test-password-123']);

        $resp = $this->get(route('report.export', [$check, 'json']));
        $resp->assertOk();
        $resp->assertHeader('Content-Type', 'application/json');
        $this->assertStringContainsString('attachment; filename="exposure-check-1-username.json"', (string) $resp->headers->get('Content-Disposition'));

        $json = $resp->json();
        $this->assertSame('Exposure-Check-OSINT', $json['product']);
        $this->assertSame('doc***', $json['check']['identifier_masked']);
        $this->assertSame(88, $json['check']['exposure_score']);
        $this->assertCount(3, $json['sources']);
        $this->assertSame('confirmed', $json['sources'][0]['data']['found_accounts'][0]['confidence']);

        // privacy: masked identifier only + credential material re-stripped
        $raw = (string) $resp->getContent();
        $this->assertStringNotContainsString('hunter2', $raw);
        $this->assertStringNotContainsString('credential_lines', $raw);
        $this->assertStringNotContainsString('doctor@', $raw);
    }

    public function test_csv_export_is_one_row_per_source_with_bom(): void
    {
        $check = $this->makeCheck();
        $this->post('/login', ['password' => 'test-password-123']);

        $resp = $this->get(route('report.export', [$check, 'csv']));
        $resp->assertOk();
        $this->assertStringContainsString('text/csv', (string) $resp->headers->get('Content-Type'));
        $this->assertStringContainsString('attachment; filename=exposure-check-1-username.csv', (string) $resp->headers->get('Content-Disposition'));

        $body = $resp->streamedContent();
        $this->assertStringStartsWith("\xEF\xBB\xBF", $body); // UTF-8 BOM for Excel
        $this->assertStringContainsString('source_key,source_label', $body);
        $this->assertStringContainsString('maigret', $body);
        $this->assertStringContainsString('xposedornot', $body);
        // 1 header + 3 source rows = 4 lines
        $this->assertCount(4, array_filter(explode("\n", trim($body, "\n"))));
        $this->assertStringNotContainsString('hunter2', $body);
    }

    public function test_password_check_exports_honest_empty_sources(): void
    {
        $check = ExposureCheck::create([
            'type' => 'password',
            'identifier_hash' => str_repeat('b', 64),
            'identifier_masked' => 'SHA-1 prefix 21B**',
            'total_sources' => 1,
            'hits' => 0,
            'exposure_score' => null,
            'results' => null,
        ]);
        $this->post('/login', ['password' => 'test-password-123']);

        $csv = $this->get(route('report.export', [$check, 'csv']))->streamedContent();
        $this->assertStringContainsString('(none stored)', $csv);
        $this->assertStringContainsString('No per-source data is stored by design', $csv);

        $json = $this->get(route('report.export', [$check, 'json']))->json();
        $this->assertSame([], $json['sources']);
        $this->assertNull($json['check']['exposure_score']);
    }

    public function test_unknown_format_is_404(): void
    {
        $check = $this->makeCheck();
        $this->post('/login', ['password' => 'test-password-123']);
        $this->get('/report/' . $check->id . '/export/xml')->assertNotFound();
    }
}
