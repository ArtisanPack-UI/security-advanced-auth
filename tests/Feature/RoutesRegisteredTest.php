<?php

declare( strict_types=1 );

use Illuminate\Support\Facades\Route;

it( 'registers all social, sso, and webauthn routes when enabled', function (): void {
    $expected = [
        'security-advanced-auth.social.redirect',
        'security-advanced-auth.social.callback',
        'security-advanced-auth.social.unlink',
        'security-advanced-auth.sso.login',
        'security-advanced-auth.sso.callback',
        'security-advanced-auth.sso.logout',
        'security-advanced-auth.sso.logout.callback',
        'security-advanced-auth.sso.metadata',
        'security-advanced-auth.webauthn.register.options',
        'security-advanced-auth.webauthn.register.verify',
        'security-advanced-auth.webauthn.authenticate.options',
        'security-advanced-auth.webauthn.authenticate.verify',
    ];

    $routes = collect( Route::getRoutes()->getRoutes() )
        ->map( fn ( $route ) => $route->getName() )
        ->filter()
        ->values()
        ->all();

    foreach ( $expected as $name ) {
        expect( $routes )->toContain( $name );
    }
} );
