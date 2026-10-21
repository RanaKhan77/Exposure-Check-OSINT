<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // One Exposure Check audit row per run (single-admin CE - no user
        // table needed; quota is counted per install per day).
        Schema::create('exposure_checks', function (Blueprint $table) {
            $table->id();
            $table->string('type', 12)->index();
            $table->string('identifier_hash', 64)->index();
            $table->string('identifier_masked', 120);
            $table->unsignedSmallInteger('total_sources')->default(0);
            $table->unsignedSmallInteger('hits')->default(0);
            $table->unsignedSmallInteger('exposure_score')->nullable();
            $table->json('results')->nullable();
            $table->timestamps();

            $table->index(['type', 'identifier_hash']);
            $table->index(['created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('exposure_checks');
    }
};
