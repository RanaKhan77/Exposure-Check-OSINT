<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Modules\Osint\OsintCheckService;
use App\Modules\Osint\Sources\OsintSource;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Storage;

/**
 * ec:doctor — install self-test (v1.1).
 *
 * Runs the full health matrix WITHOUT running a real check:
 *   1. environment   — PHP version, required extensions, app key, admin password
 *   2. storage       — writability, maigret site database validity
 *   3. database      — reachable, migrations applied, audit table present
 *   4. source health — every registered adapter class instantiates and resolves
 *   5. reachability  — ONE lightweight probe per source (the first request
 *      spec for a synthetic identifier), fired in parallel with a short
 *      timeout, so the whole doctor run finishes in seconds.
 *
 * Honesty rules (same as the product):
 *   - a source that answers with ANY HTTP status is reachable (PASS);
 *   - transport failure / timeout is WARN (unreachable now, never "broken");
 *   - only config-level problems (missing extension, unwritable storage,
 *     invalid site DB, dead database) are FAIL.
 *
 * Exit code: 0 = no FAIL (WARN allowed), 1 = at least one FAIL.
 * Output: human table by default, structured JSON with --json.
 */
class EcDoctorCommand extends Command
{
    protected $signature = 'ec:doctor
        {--json : Emit machine-readable JSON instead of the human table}
        {--timeout=8 : Per-source network probe timeout in seconds (2-30)}';

    protected $description = 'Self-test the install: environment, storage, database, source registry and live reachability of every source';

    /** @var array<int, array{status: string, name: string, detail: string}> */
    private array $checks = [];

    /** @var array<int, array{key: string, label: string, status: string, http: ?int, detail: string}> */
    private array $sourceProbes = [];

    public function handle(): int
    {
        $timeout = max(2, min(30, (int) $this->option('timeout')));

        $this->checkEnvironment();
        $this->checkStorage();
        $this->checkDatabase();
        $this->checkSourceRegistry();
        $this->probeSources($timeout);

        $passed = count(array_filter($this->checks, static fn ($c) => $c['status'] === 'PASS'))
            + count(array_filter($this->sourceProbes, static fn ($p) => $p['status'] === 'PASS'));
        $warned = count(array_filter($this->checks, static fn ($c) => $c['status'] === 'WARN'))
            + count(array_filter($this->sourceProbes, static fn ($p) => $p['status'] === 'WARN'));
        $failed = count(array_filter($this->checks, static fn ($c) => $c['status'] === 'FAIL'))
            + count(array_filter($this->sourceProbes, static fn ($p) => $p['status'] === 'FAIL'));

        if ($this->option('json')) {
            $this->line((string) json_encode([
                'ok' => $failed === 0,
                'passed' => $passed,
                'warned' => $warned,
                'failed' => $failed,
                'checks' => $this->checks,
                'sources' => $this->sourceProbes,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        } else {
            $rows = array_map(static fn ($c) => [$c['status'], $c['name'], $c['detail']], $this->checks);
            foreach ($this->sourceProbes as $p) {
                $rows[] = [$p['status'], 'source: ' . $p['key'], $p['detail']];
            }
            $this->table(['Status', 'Check', 'Detail'], $rows);
            $this->newLine();
            $this->info(sprintf('%d passed · %d warned · %d failed', $passed, $warned, $failed));
            if ($failed > 0) {
                $this->error('Install self-test FAILED — fix the FAIL rows above (most are one .env or permission change).');
            } elseif ($warned > 0) {
                $this->warn('Install is functional; WARN rows are transient (a source may be down right now).');
            } else {
                $this->info('Install is healthy — all sources reachable.');
            }
        }

        return $failed > 0 ? self::FAILURE : self::SUCCESS;
    }

    private function add(string $status, string $name, string $detail): void
    {
        $this->checks[] = ['status' => $status, 'name' => $name, 'detail' => $detail];
    }

    private function checkEnvironment(): void
    {
        $this->add(PHP_VERSION_ID >= 80200 ? 'PASS' : 'FAIL', 'PHP version', PHP_VERSION . (PHP_VERSION_ID >= 80200 ? '' : ' — PHP 8.2+ required'));

        $required = ['curl', 'dom', 'mbstring', 'openssl', 'pdo_sqlite', 'sqlite3', 'json'];
        $missing = array_values(array_filter($required, static fn ($e) => !extension_loaded($e)));
        $this->add($missing === [] ? 'PASS' : 'FAIL', 'PHP extensions', $missing === [] ? 'all required extensions loaded' : 'missing: ' . implode(', ', $missing));

        $this->add(config('app.key') !== null && config('app.key') !== '' ? 'PASS' : 'FAIL', 'App key', config('app.key') ? 'set' : 'missing — run: php artisan key:generate');

        $admin = (string) config('app.admin_password', '');
        $this->add($admin !== '' ? 'PASS' : 'WARN', 'Admin password', $admin !== '' ? 'configured (login possible)' : 'ADMIN_PASSWORD empty — login is impossible until you set it in .env');
    }

    private function checkStorage(): void
    {
        $dirs = [storage_path('app'), storage_path('framework'), storage_path('logs'), base_path('bootstrap/cache')];
        $unwritable = array_values(array_filter($dirs, static fn ($d) => !is_dir($d) || !is_writable($d)));
        $this->add($unwritable === [] ? 'PASS' : 'FAIL', 'Storage writable', $unwritable === [] ? 'storage + bootstrap/cache writable' : 'not writable: ' . implode(', ', array_map('realpath', $unwritable)));

        try {
            $raw = Storage::disk('local')->get('maigret/sites.json');
            $doc = is_string($raw) ? json_decode($raw, true) : null;
            $n = is_array($doc) && isset($doc['sites']) && is_array($doc['sites']) ? count($doc['sites']) : 0;
            if ($n >= 100) {
                $this->add('PASS', 'Maigret site database', $n . ' sites loaded (sites.json valid)');
            } elseif ($n > 0) {
                $this->add('WARN', 'Maigret site database', 'only ' . $n . ' sites — username footprint checks will be thin (expected >= 100)');
            } else {
                $this->add('FAIL', 'Maigret site database', 'storage/app/maigret/sites.json missing or invalid JSON — username checks will be unavailable');
            }
        } catch (\Throwable $e) {
            $this->add('FAIL', 'Maigret site database', 'unreadable: ' . $e->getMessage());
        }
    }

    private function checkDatabase(): void
    {
        $connection = (string) config('database.default', 'sqlite');

        if ($connection === 'sqlite' && (string) config('database.connections.sqlite.database') === ':memory:') {
            $this->add('PASS', 'Database', 'in-memory (testing)');

            return;
        }

        try {
            DB::connection($connection)->getPdo();
            $this->add('PASS', 'Database', 'reachable (' . $connection . ')');
        } catch (\Throwable $e) {
            $this->add('FAIL', 'Database', 'not reachable: ' . mb_substr($e->getMessage(), 0, 160));

            return;
        }

        try {
            $files = glob(database_path('migrations/*.php')) ?: [];
            $applied = Schema::hasTable('migrations') ? DB::table('migrations')->count() : 0;
            if ($applied >= count($files) && $files !== []) {
                $this->add('PASS', 'Migrations', $applied . ' applied, none pending');
            } elseif ($files === []) {
                $this->add('WARN', 'Migrations', 'no migration files found');
            } else {
                $this->add('WARN', 'Migrations', (count($files) - $applied) . ' pending — run: php artisan migrate');
            }
        } catch (\Throwable $e) {
            $this->add('WARN', 'Migrations', 'could not inspect: ' . mb_substr($e->getMessage(), 0, 160));
        }

        try {
            if (Schema::hasTable('exposure_checks')) {
                $this->add('PASS', 'Audit table', 'exposure_checks present (' . DB::table('exposure_checks')->count() . ' stored checks)');
            } else {
                $this->add('WARN', 'Audit table', 'exposure_checks missing — run: php artisan migrate');
            }
        } catch (\Throwable $e) {
            $this->add('WARN', 'Audit table', 'could not inspect: ' . mb_substr($e->getMessage(), 0, 160));
        }
    }

    /** @return array<int, OsintSource> */
    private function sources(): array
    {
        $out = [];
        foreach (OsintCheckService::SOURCES as $cls) {
            $out[] = app($cls);
        }

        return $out;
    }

    private function checkSourceRegistry(): void
    {
        $ok = 0;
        $errors = [];
        foreach (OsintCheckService::SOURCES as $cls) {
            try {
                $src = app($cls);
                $src->key();
                $src->label();
                $src->category();
                $ok++;
            } catch (\Throwable $e) {
                $errors[] = class_basename($cls) . ': ' . mb_substr($e->getMessage(), 0, 80);
            }
        }
        $this->add($errors === [] ? 'PASS' : 'FAIL', 'Source registry', $errors === []
            ? $ok . ' source adapters registered'
            : implode('; ', $errors));
    }

    private function probeSources(int $timeout): void
    {
        $samples = [
            'email' => 'doctor@example.com',
            'username' => 'doctor',
            'phone' => '+8801700000000',
            'password' => '21BD1', // k-anonymity: synthetic 5-hex prefix, harmless range query
            'ip' => '8.8.8.8',
        ];

        $probes = [];
        foreach ($this->sources() as $src) {
            $type = null;
            foreach (array_keys($samples) as $t) {
                if ($src->supports((string) $t)) {
                    $type = (string) $t;

                    break;
                }
            }
            if ($type === null) {
                $this->sourceProbes[] = ['key' => $src->key(), 'label' => $src->label(), 'status' => 'WARN', 'http' => null, 'detail' => 'no supported check type — skipped'];

                continue;
            }
            try {
                $specs = $src->requests($type, $samples[$type]);
            } catch (\Throwable $e) {
                $this->sourceProbes[] = ['key' => $src->key(), 'label' => $src->label(), 'status' => 'WARN', 'http' => null, 'detail' => 'probe build failed: ' . mb_substr($e->getMessage(), 0, 80)];

                continue;
            }
            if ($specs === []) {
                $this->sourceProbes[] = ['key' => $src->key(), 'label' => $src->label(), 'status' => 'WARN', 'http' => null, 'detail' => 'no probe request declared'];

                continue;
            }
            $probes[$src->key()] = ['label' => $src->label(), 'spec' => $specs[0]];
        }

        if ($probes === []) {
            return;
        }

        try {
            $responses = Http::pool(function ($pool) use ($probes, $timeout) {
                $pending = [];
                foreach ($probes as $key => $p) {
                    $req = $pool->as($key)->timeout($timeout);
                    $headers = $p['spec']['headers'] ?? [];
                    if (is_array($headers) && $headers !== []) {
                        $req = $req->withHeaders($headers);
                    }
                    $pending[] = strtoupper((string) ($p['spec']['method'] ?? 'GET')) === 'POST'
                        ? $req->post((string) $p['spec']['url'], $p['spec']['body'] ?? [])
                        : $req->get((string) $p['spec']['url']);
                }

                return $pending;
            });
        } catch (\Throwable $e) {
            foreach ($probes as $key => $p) {
                $this->sourceProbes[] = ['key' => $key, 'label' => $p['label'], 'status' => 'WARN', 'http' => null, 'detail' => 'probe pool failed: ' . mb_substr($e->getMessage(), 0, 80)];
            }

            return;
        }

        foreach ($probes as $key => $p) {
            $resp = $responses[$key] ?? null;
            // Pools surface transport failures either as a Response with
            // status 0 or as the exception object itself — handle both.
            if ($resp instanceof \Illuminate\Http\Client\Response) {
                $status = (int) $resp->status();
            } elseif ($resp instanceof \Throwable) {
                $status = 0;
            } else {
                $status = 0;
            }
            if ($status > 0) {
                $this->sourceProbes[] = ['key' => $key, 'label' => $p['label'], 'status' => 'PASS', 'http' => $status, 'detail' => 'reachable (HTTP ' . $status . ')'];
            } else {
                $this->sourceProbes[] = ['key' => $key, 'label' => $p['label'], 'status' => 'WARN', 'http' => null, 'detail' => 'unreachable (timeout / DNS / transport) — source card will honestly show unavailable'];
            }
        }
    }
}
