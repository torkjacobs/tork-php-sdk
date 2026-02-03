<?php

declare(strict_types=1);

namespace Tork\Governance\Laravel;

use Illuminate\Support\ServiceProvider;
use Tork\Governance\Core\Tork;
use Tork\Governance\Middleware\LaravelMiddleware;

/**
 * Laravel service provider for Tork Governance.
 */
class TorkServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../../config/tork.php',
            'tork'
        );

        $this->app->singleton(Tork::class, function ($app) {
            return new Tork(config('tork', []));
        });

        $this->app->singleton(LaravelMiddleware::class, function ($app) {
            return new LaravelMiddleware(
                $app->make(Tork::class),
                config('tork.middleware', [])
            );
        });
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../../config/tork.php' => config_path('tork.php'),
            ], 'tork-config');
        }

        // Register middleware alias
        $router = $this->app['router'];
        $router->aliasMiddleware('tork', LaravelMiddleware::class);
    }
}
