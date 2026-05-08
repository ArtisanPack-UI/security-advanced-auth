<?php

declare( strict_types=1 );

use ArtisanPackUI\SecurityAdvancedAuth\SecurityAdvancedAuth;

it( 'binds the security-advanced-auth singleton', function (): void {
    expect( app( 'security-advanced-auth' ) )->toBeInstanceOf( SecurityAdvancedAuth::class );
} );

it( 'returns the same instance on subsequent resolutions', function (): void {
    expect( app( 'security-advanced-auth' ) )->toBe( app( 'security-advanced-auth' ) );
} );

it( 'exposes the security_advanced_auth() helper', function (): void {
    expect( security_advanced_auth() )->toBeInstanceOf( SecurityAdvancedAuth::class );
} );
