<?php

declare(strict_types=1);

namespace App\Providers;

use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        //
    }

    public function boot(): void
    {
        // The CE has no destructive admin operations; keep the Laravel
        // default gate behavior explicit.
        Gate::define('admin', fn () => true);
    }
}
