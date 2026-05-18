<?php

/**
 * SocialAuthManager social authentication class.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAdvancedAuth
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts\SocialProviderInterface;
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\Providers\AppleProvider;
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\Providers\FacebookProvider;
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\Providers\GenericOidcProvider;
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\Providers\GitHubProvider;
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\Providers\GoogleProvider;
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\Providers\LinkedInProvider;
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\Providers\MicrosoftProvider;
use ArtisanPackUI\SecurityAdvancedAuth\Models\SocialIdentity;
use Exception;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Session;
use InvalidArgumentException;
use RuntimeException;

class SocialAuthManager
{
    /**
     * The registered providers.
     *
     * @var array<string, SocialProviderInterface>
     */
    protected array $providers = [];

    /**
     * The provider class map.
     *
     * @var array<string, class-string<SocialProviderInterface>>
     */
    protected array $providerMap = [
        'google'    => GoogleProvider::class,
        'microsoft' => MicrosoftProvider::class,
        'github'    => GitHubProvider::class,
        'facebook'  => FacebookProvider::class,
        'apple'     => AppleProvider::class,
        'linkedin'  => LinkedInProvider::class,
    ];

    /**
     * Create a new social auth manager instance.
     */
    public function __construct()
    {
        $this->bootProviders();
    }

    /**
     * Register a provider.
     *
     * @param  array<string, mixed>  $config
     */
    public function registerProvider( string $name, array $config ): void
    {
        $providerClass = $this->providerMap[ $name ] ?? null;

        if ( null === $providerClass ) {
            // Check if it's a generic OIDC provider
            if ( ! empty( $config['issuer_url'] ) ) {
                $config['name']           = $name;
                $this->providers[ $name ] = new GenericOidcProvider( $config );

                return;
            }

            throw new InvalidArgumentException( "Unknown social provider: {$name}" );
        }

        // Add redirect URI to config
        if ( empty( $config['redirect_uri'] ) ) {
            $config['redirect_uri'] = $this->buildRedirectUri( $name );
        }

        $this->providers[ $name ] = new $providerClass( $config );
    }

    /**
     * Get a provider by name.
     */
    public function provider( string $name ): SocialProviderInterface
    {
        if ( ! isset( $this->providers[ $name ] ) ) {
            throw new InvalidArgumentException( "Social provider not registered: {$name}" );
        }

        return $this->providers[ $name ];
    }

    /**
     * Check if a provider is registered and enabled.
     */
    public function hasProvider( string $name ): bool
    {
        return isset( $this->providers[ $name ] );
    }

    /**
     * Get all registered providers.
     *
     * @return array<string, SocialProviderInterface>
     */
    public function getProviders(): array
    {
        return $this->providers;
    }

    /**
     * Get all enabled provider names.
     *
     * @return array<string>
     */
    public function getEnabledProviders(): array
    {
        return array_keys( $this->providers );
    }

    /**
     * Initiate the OAuth flow for a provider.
     *
     * @param  array<string, mixed>  $options
     */
    public function redirect( string $providerName, array $options = [] ): string
    {
        $provider = $this->provider( $providerName );

        $state = $provider->generateState();
        Session::put( "social_auth.{$providerName}.state", $state );

        $options['state'] = $state;

        return $provider->getAuthorizationUrl( $options );
    }

    /**
     * Handle the OAuth callback.
     *
     * @return array{user: SocialUser, tokens: array{access_token: string, refresh_token: ?string, expires_in: ?int}}
     */
    public function callback( string $providerName, string $code, string $state ): array
    {
        $provider = $this->provider( $providerName );

        // Validate state
        $expectedState = Session::pull( "social_auth.{$providerName}.state" );

        if ( ! $expectedState || ! $provider->validateState( $state, $expectedState ) ) {
            throw new RuntimeException( 'Invalid state parameter. Possible CSRF attack.' );
        }

        // Exchange code for tokens
        $tokens = $provider->getAccessToken( $code );

        // Special handling for Apple
        if ( 'apple' === $providerName && $provider instanceof AppleProvider ) {
            $user = $provider->getUserFromIdToken(
                $tokens['id_token'] ?? '',
                Session::pull( 'social_auth.apple.user_data' ),
            );
        } else {
            // Get user info
            $user = $provider->getUser( $tokens['access_token'] );
        }

        // Validate hosted domain restriction for Google
        if ( 'google' === $providerName && $provider instanceof GoogleProvider ) {
            if ( ! $provider->validateHostedDomain( $user ) ) {
                throw new RuntimeException( 'Email domain not allowed. Please use an email from the authorized domain.' );
            }
        }

        return [
            'user'   => $user,
            'tokens' => $tokens,
        ];
    }

    /**
     * Find or create a user from social authentication.
     *
     * @param  array{access_token: string, refresh_token: ?string, expires_in: ?int}  $tokens
     */
    public function findOrCreateUser( SocialUser $socialUser, array $tokens ): ?Authenticatable
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        // First, try to find by social identity
        $identity = SocialIdentity::byProviderUserId(
            $socialUser->getProvider(),
            $socialUser->getId(),
        )->first();

        if ( $identity ) {
            // Update tokens
            $identity->updateTokens( $tokens );

            return $identity->user;
        }

        // If linking is not allowed and auto-register is disabled, return null
        if ( ! config( 'artisanpack.security-advanced-auth.social.allow_linking' ) && ! config( 'artisanpack.security-advanced-auth.social.auto_register' ) ) {
            return null;
        }

        // Try to find existing user by email
        $user = null;
        if ( $socialUser->hasEmail() && config( 'artisanpack.security-advanced-auth.social.allow_linking' ) ) {
            $user = $userModel::where( 'email', $socialUser->getEmail() )->first();
        }

        // Auto-register new user if configured
        if ( null === $user && config( 'artisanpack.security-advanced-auth.social.auto_register' ) ) {
            if ( config( 'artisanpack.security-advanced-auth.social.require_email' ) && ! $socialUser->hasEmail() ) {
                throw new RuntimeException( 'Email is required for registration' );
            }

            $user = $this->createUserFromSocial( $socialUser );
        }

        if ( null === $user ) {
            return null;
        }

        // Link the social identity
        $this->linkIdentity( $user, $socialUser, $tokens );

        return $user;
    }

    /**
     * Link a social identity to a user.
     *
     * @param  array{access_token: string, refresh_token: ?string, expires_in: ?int}  $tokens
     */
    public function linkIdentity( Authenticatable $user, SocialUser $socialUser, array $tokens ): SocialIdentity
    {
        return $user->linkSocialIdentity(
            $socialUser->getProvider(),
            $socialUser->getId(),
            [
                'email'            => $socialUser->getEmail(),
                'name'             => $socialUser->getName(),
                'avatar'           => $socialUser->getAvatar(),
                'access_token'     => $tokens['access_token'],
                'refresh_token'    => $tokens['refresh_token'] ?? null,
                'token_expires_at' => isset( $tokens['expires_in'] )
                    ? now()->addSeconds( $tokens['expires_in'] )
                    : null,
                'scopes'   => $socialUser->getScopes(),
                'raw_data' => $socialUser->getRawData(),
            ],
        );
    }

    /**
     * Unlink a social identity from a user.
     */
    public function unlinkIdentity( Authenticatable $user, string $provider ): bool
    {
        // Don't allow unlinking if it's the only auth method
        if ( method_exists( $user, 'isSocialOnlyAuth' ) && $user->isSocialOnlyAuth() ) {
            $linkedProviders = method_exists( $user, 'getLinkedProviders' )
                ? $user->getLinkedProviders()
                : [];

            if ( count( $linkedProviders ) <= 1 ) {
                throw new RuntimeException( 'Cannot unlink the only authentication method' );
            }
        }

        return $user->unlinkSocialIdentity( $provider );
    }

    /**
     * Refresh tokens for a social identity.
     */
    public function refreshTokens( SocialIdentity $identity ): bool
    {
        if ( ! $identity->refresh_token ) {
            return false;
        }

        $provider = $this->provider( $identity->provider );

        if ( ! $provider->supportsRefresh() ) {
            return false;
        }

        try {
            $tokens = $provider->refreshAccessToken( $identity->refresh_token );
            $identity->updateTokens( $tokens );

            return true;
        } catch ( Exception ) {
            return false;
        }
    }

    /**
     * Extend the provider map with a custom provider.
     *
     * @param  class-string<SocialProviderInterface>  $providerClass
     */
    public function extend( string $name, string $providerClass ): void
    {
        $this->providerMap[ $name ] = $providerClass;
    }

    /**
     * Boot configured providers.
     */
    protected function bootProviders(): void
    {
        $providersConfig = config( 'artisanpack.security-advanced-auth.social.providers', [] );

        foreach ( $providersConfig as $name => $config ) {
            if ( ! ( $config['enabled'] ?? false ) ) {
                continue;
            }

            $this->registerProvider( $name, $config );
        }
    }

    /**
     * Build the redirect URI for a provider.
     */
    protected function buildRedirectUri( string $provider ): string
    {
        $baseUrl = config( 'artisanpack.security-advanced-auth.social.callbacks.base_url', config( 'app.url' ) );
        $path    = config( 'artisanpack.security-advanced-auth.social.callbacks.path', 'auth/social/{provider}/callback' );

        return rtrim( $baseUrl, '/' ) . '/' . str_replace( '{provider}', $provider, $path );
    }

    /**
     * Create a new user from social data.
     */
    protected function createUserFromSocial( SocialUser $socialUser ): Authenticatable
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        $userData = [
            'email'             => $socialUser->getEmail(),
            'name'              => $socialUser->getName() ?? $socialUser->getEmail(),
            'email_verified_at' => $socialUser->isEmailVerified() ? now() : null,
        ];

        $user = $userModel::create( $userData );

        // Assign default role if configured
        $defaultRole = config( 'artisanpack.security-advanced-auth.social.default_role' );
        if ( $defaultRole && method_exists( $user, 'assignRole' ) ) {
            $user->assignRole( $defaultRole );
        }

        return $user;
    }
}
