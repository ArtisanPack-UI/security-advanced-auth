<?php

declare( strict_types=1 );

use ArtisanPackUI\SecurityAdvancedAuth\Http\Controllers\SocialAuthController;
use ArtisanPackUI\SecurityAdvancedAuth\Http\Controllers\SsoController;
use ArtisanPackUI\SecurityAdvancedAuth\Http\Controllers\WebAuthnController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Security Advanced Auth Routes
|--------------------------------------------------------------------------
|
| Social OAuth, SSO (SAML / OIDC / LDAP), and WebAuthn callback routes.
|
| The whole file is loaded only when
| `artisanpack.security-advanced-auth.routes.enabled` is true (default).
|
| Each route group respects its own middleware list — the social group
| typically wants 'web', WebAuthn JSON endpoints typically want 'api'.
|
*/

$prefix = config( 'artisanpack.security-advanced-auth.routes.prefix', 'auth' );

// --- Social OAuth ----------------------------------------------------------
$socialMiddleware = config( 'artisanpack.security-advanced-auth.routes.social.middleware', ['web'] );

Route::middleware( $socialMiddleware )
    ->prefix( "{$prefix}/social" )
    ->name( 'security-advanced-auth.social.' )
    ->group( function (): void {
        Route::get( '/{provider}/redirect', [SocialAuthController::class, 'redirect'] )->name( 'redirect' );
        Route::get( '/{provider}/callback', [SocialAuthController::class, 'callback'] )->name( 'callback' );
        Route::post( '/{provider}/unlink', [SocialAuthController::class, 'unlink'] )
            ->middleware( 'auth' )
            ->name( 'unlink' );
    } );

// --- SSO (SAML / OIDC / LDAP) ----------------------------------------------
$ssoMiddleware = config( 'artisanpack.security-advanced-auth.routes.sso.middleware', ['web'] );

Route::middleware( $ssoMiddleware )
    ->prefix( "{$prefix}/sso" )
    ->name( 'security-advanced-auth.sso.' )
    ->group( function (): void {
        Route::get( '/{slug}/login', [SsoController::class, 'login'] )->name( 'login' );
        // Both GET and POST — OIDC implicit / auth-code flows use GET, SAML ACS uses POST.
        Route::match( ['GET', 'POST'], '/{slug}/callback', [SsoController::class, 'callback'] )->name( 'callback' );
        Route::post( '/{slug}/logout', [SsoController::class, 'logout'] )->name( 'logout' );
        Route::get( '/{slug}/logout/callback', [SsoController::class, 'logoutCallback'] )->name( 'logout.callback' );
        Route::get( '/{slug}/metadata', [SsoController::class, 'metadata'] )->name( 'metadata' );
    } );

// --- WebAuthn / FIDO2 ------------------------------------------------------
//
// `registerVerify` requires the authenticated user; `authenticateVerify`
// calls `Auth::login()` which needs an active session to persist. Both are
// state-changing POSTs, so they need CSRF protection. The default `web`
// middleware group provides StartSession + VerifyCsrfToken; the bare `api`
// group typically does not. Host apps overriding this config must include
// session + CSRF middleware for the verify endpoints (the *_options
// endpoints are read-only and safe under `api`).
$webauthnMiddleware = config( 'artisanpack.security-advanced-auth.routes.webauthn.middleware', ['web'] );

Route::middleware( $webauthnMiddleware )
    ->prefix( "{$prefix}/webauthn" )
    ->name( 'security-advanced-auth.webauthn.' )
    ->group( function (): void {
        Route::post( '/register/options', [WebAuthnController::class, 'registerOptions'] )->name( 'register.options' );
        Route::post( '/register/verify', [WebAuthnController::class, 'registerVerify'] )->name( 'register.verify' );
        Route::post( '/authenticate/options', [WebAuthnController::class, 'authenticateOptions'] )->name( 'authenticate.options' );
        Route::post( '/authenticate/verify', [WebAuthnController::class, 'authenticateVerify'] )->name( 'authenticate.verify' );
    } );
