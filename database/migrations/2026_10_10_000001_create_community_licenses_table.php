<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Single-row local license state for this installation.
        Schema::create('community_licenses', function (Blueprint $table) {
            $table->id();
            $table->string('license_key', 64)->nullable()->index();
            $table->string('status', 24)->default('trial');   // trial | licensed | revoked | inactive
            $table->string('product', 32)->default('exposure-check'); // install telemetry separation
            $table->string('domain', 190)->nullable();
            $table->string('install_id', 64)->nullable()->index();
            $table->timestamp('trial_started_at')->nullable();
            $table->timestamp('trial_ends_at')->nullable();
            $table->timestamp('activated_at')->nullable();
            $table->timestamp('last_validated_at')->nullable();
            $table->json('response_payload')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('community_licenses');
    }
};
