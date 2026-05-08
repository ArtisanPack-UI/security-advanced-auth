<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth;

use Illuminate\Support\ServiceProvider;

/**
 * Security Advanced Auth service provider.
 *
 * Scaffold-only at this stage. Bindings, migrations, views, and Livewire
 * component registrations are added once the source files are extracted from
 * artisanpack-ui/security 1.x in a follow-up PR.
 *
 * @since 1.0.0
 */
class SecurityAdvancedAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton( 'security-advanced-auth', function ( $app ) {
            return new SecurityAdvancedAuth();
        } );
    }

    public function boot(): void
    {
        // Bootstrapping arrives with the content-extraction PR.
    }
}
