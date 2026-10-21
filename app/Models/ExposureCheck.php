<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * One Exposure Check audit row (Community Edition).
 *
 * PRIVACY CONTRACT:
 *   - identifier_hash : salted SHA-256 (app key + type + identifier) - the raw
 *     identifier is NEVER stored here.
 *   - identifier_masked : display-safe masked form (j***n@gmail.com).
 *   - results : per-source aggregated results (no credential material -
 *     ProxyNova lines are stripped at the source-adapter level BEFORE
 *     anything reaches this table).
 */
class ExposureCheck extends Model
{
    protected $table = 'exposure_checks';

    protected $fillable = [
        'type',
        'identifier_hash',
        'identifier_masked',
        'total_sources',
        'hits',
        'exposure_score',
        'results',
    ];

    protected $casts = [
        'results' => 'array',
        'exposure_score' => 'integer',
        'total_sources' => 'integer',
        'hits' => 'integer',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];
}
