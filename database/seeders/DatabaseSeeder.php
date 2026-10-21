<?php

declare(strict_types=1);

namespace Database\Seeders;

use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    /**
     * No seed data needed: the license trial row is created on first call,
     * settings default in SettingsService, and the admin password lives in
     * .env (container entrypoint generates it on first boot).
     */
    public function run(): void
    {
        //
    }
}
