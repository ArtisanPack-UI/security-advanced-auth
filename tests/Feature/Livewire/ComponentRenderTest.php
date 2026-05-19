<?php

declare( strict_types=1 );

use ArtisanPackUI\SecurityAdvancedAuth\Livewire\BiometricManager;
use ArtisanPackUI\SecurityAdvancedAuth\Livewire\DeviceManager;
use ArtisanPackUI\SecurityAdvancedAuth\Livewire\SocialAccountsManager;
use ArtisanPackUI\SecurityAdvancedAuth\Livewire\SuspiciousActivityList;
use ArtisanPackUI\SecurityAdvancedAuth\Livewire\WebAuthnCredentialsManager;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Support\Facades\Schema;
use Livewire\Livewire;

beforeEach( function (): void {
    // Migrations alter a `users` table that doesn't exist in testbench.
    if ( ! Schema::hasTable( 'users' ) ) {
        Schema::create( 'users', function ( Blueprint $table ): void {
            $table->id();
            $table->string( 'name' );
            $table->string( 'email' )->unique();
            $table->timestamp( 'email_verified_at' )->nullable();
            $table->string( 'password' );
            $table->rememberToken();
            $table->timestamps();
        } );
    }

    $this->artisan( 'migrate' );

    $this->actingAs( new class extends Authenticatable {
        public $id = 1;

        protected $guarded = [];

        public function getAuthIdentifier()
        {
            return 1;
        }
    } );
} );

it( 'renders the BiometricManager Livewire component', function (): void {
    Livewire::test( BiometricManager::class )
        ->assertStatus( 200 );
} );

it( 'renders the DeviceManager Livewire component', function (): void {
    Livewire::test( DeviceManager::class )
        ->assertStatus( 200 );
} );

it( 'renders the SocialAccountsManager Livewire component', function (): void {
    Livewire::test( SocialAccountsManager::class )
        ->assertStatus( 200 );
} );

it( 'renders the SuspiciousActivityList Livewire component', function (): void {
    Livewire::test( SuspiciousActivityList::class )
        ->assertStatus( 200 );
} );

it( 'renders the WebAuthnCredentialsManager Livewire component', function (): void {
    Livewire::test( WebAuthnCredentialsManager::class )
        ->assertStatus( 200 );
} );
