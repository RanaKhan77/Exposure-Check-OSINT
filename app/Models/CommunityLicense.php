<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class CommunityLicense extends Model
{
    protected $table = 'community_licenses';

    protected $fillable = [
        'license_key', 'status', 'product', 'domain', 'install_id',
        'trial_started_at', 'trial_ends_at', 'activated_at',
        'last_validated_at', 'response_payload',
    ];

    protected $casts = [
        'trial_started_at' => 'datetime',
        'trial_ends_at' => 'datetime',
        'activated_at' => 'datetime',
        'last_validated_at' => 'datetime',
        'response_payload' => 'array',
    ];

    public function isLicensed(): bool
    {
        return $this->status === 'licensed'
            && $this->license_key !== null
            && ($this->expiresAt() === null || $this->expiresAt()->isFuture());
    }

    public function expiresAt(): ?\Carbon\CarbonInterface
    {
        return $this->response_payload['expires_at'] ?? null
            ? \Illuminate\Support\Carbon::parse($this->response_payload['expires_at'])
            : null;
    }

    public function trialDaysLeft(): int
    {
        if (!$this->trial_ends_at) {
            return 0;
        }
        return max(0, (int) ceil(now()->diffInSeconds($this->trial_ends_at, false) / 86400));
    }
}
