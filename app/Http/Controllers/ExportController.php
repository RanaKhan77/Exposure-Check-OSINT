<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\ExposureCheck;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * GET /report/{check}/export/{format} — download a stored check as JSON or CSV.
 *
 * PRIVACY CONTRACT (unchanged from storage):
 *   - the identifier stays MASKED in every export (j***n@gmail.com);
 *   - credential material (ProxyNova lines) is re-stripped belt-and-braces
 *     even though storage rows are already sanitized at write time;
 *   - password checks store no per-source data by design — the CSV exports
 *     one honest summary row for them, the JSON a clear empty-source list.
 */
class ExportController extends Controller
{
    public function export(Request $request, ExposureCheck $check, string $format): Response
    {
        if (!in_array($format, ['json', 'csv'], true)) {
            abort(404);
        }

        // Belt-and-braces: never let credential material leave in an export,
        // even if a future code path ever stored it by mistake.
        $sources = $check->results ?? [];
        if (is_array($sources)) {
            foreach ($sources as $i => $src) {
                if (is_array($src) && isset($src['data']) && is_array($src['data'])) {
                    unset($sources[$i]['data']['credential_lines']);
                }
            }
        } else {
            $sources = [];
        }

        $checkedAt = $check->created_at?->utc()?->toIso8601String();

        return $format === 'json'
            ? $this->exportJson($check, $sources, $checkedAt)
            : $this->exportCsv($check, $sources, $checkedAt);
    }

    /** Full-fidelity document download (per-source detail included). */
    private function exportJson(ExposureCheck $check, array $sources, ?string $checkedAt): Response
    {
        $payload = [
            'product' => 'Exposure-Check-OSINT',
            'version' => (string) config('app.version'),
            'generated_at' => now()->utc()->toIso8601String(),
            'check' => [
                'id' => $check->id,
                'type' => $check->type,
                'identifier_masked' => $check->identifier_masked,
                'checked_at' => $checkedAt,
                'exposure_score' => $check->exposure_score,
                'hits' => $check->hits,
                'sources_assessed' => $check->total_sources,
            ],
            'sources' => array_values($sources),
            'privacy' => 'Identifiers are stored masked + salted-hashed only. Password checks store no per-source data (k-anonymity: matching happens in your browser).',
        ];

        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        return response($json === false ? '{}' : $json, 200, [
            'Content-Type' => 'application/json',
            'Content-Disposition' => 'attachment; filename="exposure-check-' . $check->id . '-' . $check->type . '.json"',
        ]);
    }

    /** Flat one-row-per-source table (opens cleanly in Excel / Sheets). */
    private function exportCsv(ExposureCheck $check, array $sources, ?string $checkedAt): Response
    {
        $filename = 'exposure-check-' . $check->id . '-' . $check->type . '.csv';

        return response()->streamDownload(function () use ($check, $sources, $checkedAt) {
            $out = fopen('php://output', 'w');
            // UTF-8 BOM so Excel detects the encoding
            fwrite($out, "\xEF\xBB\xBF");
            fputcsv($out, [
                'check_id', 'checked_at_utc', 'type', 'identifier_masked',
                'exposure_score', 'hits', 'source_key', 'source_label',
                'category', 'status', 'severity', 'summary',
            ]);

            if ($sources === []) {
                fputcsv($out, [
                    $check->id, $checkedAt, $check->type, $check->identifier_masked,
                    $check->exposure_score, $check->hits, '(none stored)', 'Password checks match in your browser',
                    '', '', '', 'No per-source data is stored by design (k-anonymity).',
                ]);
            } else {
                foreach ($sources as $src) {
                    fputcsv($out, [
                        $check->id,
                        $checkedAt,
                        $check->type,
                        $check->identifier_masked,
                        $check->exposure_score,
                        $check->hits,
                        (string) ($src['key'] ?? ''),
                        (string) ($src['label'] ?? ''),
                        (string) ($src['category'] ?? ''),
                        (string) ($src['status'] ?? ''),
                        (string) ($src['severity'] ?? ''),
                        (string) ($src['summary'] ?? ''),
                    ]);
                }
            }
            fclose($out);
        }, $filename, ['Content-Type' => 'text/csv; charset=UTF-8']);
    }
}
