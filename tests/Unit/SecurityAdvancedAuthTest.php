<?php

declare( strict_types=1 );

use ArtisanPackUI\SecurityAdvancedAuth\SecurityAdvancedAuth;

it( 'instantiates the SecurityAdvancedAuth class', function (): void {
    expect( new SecurityAdvancedAuth() )->toBeInstanceOf( SecurityAdvancedAuth::class );
} );

it( 'reports its current version', function (): void {
    expect( ( new SecurityAdvancedAuth() )->version() )->toBeString();
} );
