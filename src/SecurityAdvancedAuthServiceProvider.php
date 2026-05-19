<?php

/**
 * Security Advanced Auth service provider.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAdvancedAuth
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts\SuspiciousActivityDetectorInterface;
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Detection\SuspiciousActivityService;
use Illuminate\Support\ServiceProvider;

/**
 * Security Advanced Auth service provider.
 *
 * Bootstraps WebAuthn / FIDO2, SSO, social login, biometric, device
 * fingerprinting, and suspicious-activity-detection services for Laravel
 * applications.
 *
 * @since 1.0.0
 */
class SecurityAdvancedAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/artisanpack/security-advanced-auth.php',
            'artisanpack.security-advanced-auth',
        );

        $this->app->singleton( 'security-advanced-auth', function ( $app ) {
            return new SecurityAdvancedAuth();
        } );

        // Suspicious activity detection is the only service with a stable
        // interface today; the rest (Social, SSO, WebAuthn, Biometric, Device)
        // are wired by consumers via concrete classes since they need
        // app-specific configuration (callbacks, certs, RP IDs, etc.).
        $this->app->singleton( SuspiciousActivityService::class );
        $this->app->bind( SuspiciousActivityDetectorInterface::class, SuspiciousActivityService::class );
    }

    public function boot(): void
    {
        $this->publishes(
            [
                __DIR__ . '/../config/artisanpack/security-advanced-auth.php' => config_path( 'artisanpack/security-advanced-auth.php' ),
            ],
            'security-advanced-auth-config',
        );

        $this->publishes(
            [
                __DIR__ . '/../resources/views' => resource_path( 'views/vendor/security-advanced-auth' ),
            ],
            'security-advanced-auth-views',
        );

        $this->loadMigrationsFrom( __DIR__ . '/../database/migrations/authentication' );
        $this->loadViewsFrom( __DIR__ . '/../resources/views', 'security-advanced-auth' );

        if ( config( 'artisanpack.security-advanced-auth.routes.enabled', true ) ) {
            $this->loadRoutesFrom( __DIR__ . '/../routes/auth.php' );
        }

        $this->registerLivewireComponents();
    }

    protected function registerLivewireComponents(): void
    {
        if ( ! class_exists( \Livewire\Livewire::class ) || ! $this->app->bound( 'livewire' ) ) {
            return;
        }

        \Livewire\Livewire::component( 'webauthn-credentials-manager', Livewire\WebAuthnCredentialsManager::class );
        \Livewire\Livewire::component( 'biometric-manager', Livewire\BiometricManager::class );
        \Livewire\Livewire::component( 'device-manager', Livewire\DeviceManager::class );
        \Livewire\Livewire::component( 'social-accounts-manager', Livewire\SocialAccountsManager::class );
        \Livewire\Livewire::component( 'suspicious-activity-list', Livewire\SuspiciousActivityList::class );
    }
}
