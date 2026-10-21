<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/**
 * End-to-end smoke coverage for the flows the security review proved were
 * untested (PHASEA-CODE-REVIEW, 2026-10-21). Each test pins one regression
 * class: dead scripts (C1), unreachable password checks (C2), config-cached
 * login (C3), license 500 on fresh install (C5), settings toggles (H1).
 */
class SmokeFlowTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        config(['app.admin_password' => 'test-password-123']);
    }

    public function test_login_page_renders(): void
    {
        $resp = $this->get('/login');
        $resp->assertOk();
        $resp->assertSee('Admin password', false);
    }

    public function test_login_works_with_configured_password_and_rejects_wrong_one(): void
    {
        $this->post('/login', ['password' => 'wrong'])
            ->assertSessionHasErrors('password');

        $this->post('/login', ['password' => 'test-password-123'])
            ->assertRedirect(route('dashboard'));

        $this->get(route('dashboard'))->assertOk();
    }

    public function test_dashboard_renders_its_script_and_type_tabs(): void
    {
        $this->post('/login', ['password' => 'test-password-123']);
        $resp = $this->get(route('dashboard'));

        // C1 regression: the @push('scripts') block must actually render
        $resp->assertSee("addEventListener('submit'", false);
        // C2 regression: password must be an explicit tab
        $resp->assertSee('data-type="password"', false);
        $resp->assertSee('ox-tab', false);
        // honest source count — derived from the registry so adding a source
        // never breaks CI (v1.2.0 lesson: hardcoded "18" failed after BotCidr)
        $resp->assertSee(count(\App\Modules\Osint\OsintCheckService::SOURCES) . ' keyless sources');
    }

    public function test_api_check_accepts_five_hex_password_prefix(): void
    {
        $this->post('/login', ['password' => 'test-password-123']);

        // C5 regression: fresh install must NOT 500 while creating the
        // license row (installId file read). A 40-hex prefix must be REJECTED
        // (the k-anonymity contract).
        $this->postJson('/api/check', ['type' => 'password', 'prefix' => str_repeat('A', 40)])
            ->assertStatus(422);

        $resp = $this->postJson('/api/check', ['type' => 'password', 'prefix' => '21BD1']);
        // 200 (fetched + client-match payload) or honest 429 burst/quota - never 422/500
        $this->assertContains($resp->status(), [200, 429], 'password 5-hex check failed: ' . $resp->status());
        if ($resp->status() === 200) {
            $this->assertTrue($resp->json('ok'));
        }
    }

    public function test_api_check_rejects_bad_identifier(): void
    {
        $this->post('/login', ['password' => 'test-password-123']);
        $this->postJson('/api/check', ['type' => 'email', 'q' => 'not-an-email'])
            ->assertStatus(422);
        $this->postJson('/api/check', ['type' => 'domain', 'q' => 'example.com'])
            ->assertStatus(422); // scope rule: domains belong to the scanner CE
    }

    public function test_settings_page_renders_real_checked_attributes(): void
    {
        $this->post('/login', ['password' => 'test-password-123']);
        $resp = $this->get(route('settings'));
        $resp->assertOk();

        // H1 regression: no junk "checked(...)" attribute; real checked attrs
        $this->assertStringNotContainsString('checked(@checked', $resp->getContent());
        $this->assertStringContainsString('checked', $resp->getContent());
    }

    public function test_license_page_renders_on_fresh_install(): void
    {
        $this->post('/login', ['password' => 'test-password-123']);
        $this->get(route('license'))
            ->assertOk()
            ->assertSee('2MNY-EC-', false); // CE key format for this product
    }
}
