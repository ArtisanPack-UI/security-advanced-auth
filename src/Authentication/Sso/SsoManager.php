<?php

/**
 * SsoManager SSO class.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAdvancedAuth
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Sso;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts\SsoProviderInterface;
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Sso\Ldap\LdapAuthenticator;
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Sso\Oidc\OidcClient;
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Sso\Saml\SamlServiceProvider;
use ArtisanPackUI\SecurityAdvancedAuth\Models\SsoConfiguration;
use ArtisanPackUI\SecurityAdvancedAuth\Models\SsoIdentity;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use InvalidArgumentException;
use RuntimeException;

class SsoManager
{
    /**
     * The provider instances.
     *
     * @var array<string, SsoProviderInterface>
     */
    protected array $providers = [];

    /**
     * The provider class map.
     *
     * @var array<string, class-string<SsoProviderInterface>>
     */
    protected array $providerMap = [
        'saml' => SamlServiceProvider::class,
        'oidc' => OidcClient::class,
        'ldap' => LdapAuthenticator::class,
    ];

    /**
     * Get a provider for a configuration.
     */
    public function provider( string $slug ): SsoProviderInterface
    {
        if ( isset( $this->providers[ $slug ] ) ) {
            return $this->providers[ $slug ];
        }

        $configuration = SsoConfiguration::findBySlug( $slug );

        if ( ! $configuration ) {
            throw new InvalidArgumentException( "SSO configuration not found: {$slug}" );
        }

        if ( ! $configuration->is_enabled ) {
            throw new RuntimeException( "SSO provider is disabled: {$slug}" );
        }

        return $this->providers[ $slug ] = $this->createProvider( $configuration );
    }

    /**
     * Get all enabled SSO configurations.
     *
     * @return \Illuminate\Support\Collection<int, SsoConfiguration>
     */
    public function getEnabledConfigurations(): \Illuminate\Support\Collection
    {
        return SsoConfiguration::enabled()->get();
    }

    /**
     * Get the default SSO configuration.
     */
    public function getDefaultConfiguration(): ?SsoConfiguration
    {
        return SsoConfiguration::enabled()->default()->first();
    }

    /**
     * Initiate SSO login.
     *
     * @param  array<string, mixed>  $options
     */
    public function login( string $slug, array $options = [] ): string
    {
        $provider = $this->provider( $slug );

        return $provider->getLoginUrl( $options );
    }

    /**
     * Handle SSO callback.
     */
    public function callback( string $slug, Request $request ): SsoUser
    {
        $provider = $this->provider( $slug );

        return $provider->handleCallback( $request );
    }

    /**
     * Initiate SSO logout.
     *
     * @param  array<string, mixed>  $options
     */
    public function logout( string $slug, array $options = [] ): ?string
    {
        $provider = $this->provider( $slug );

        return $provider->getLogoutUrl( $options );
    }

    /**
     * Handle SSO logout callback.
     */
    public function handleLogout( string $slug, Request $request ): bool
    {
        $provider = $this->provider( $slug );

        return $provider->handleLogout( $request );
    }

    /**
     * Get SP metadata for a SAML configuration.
     */
    public function getMetadata( string $slug ): ?string
    {
        $provider = $this->provider( $slug );

        return $provider->getMetadata();
    }

    /**
     * Find or create a user from SSO authentication.
     */
    public function findOrCreateUser( SsoUser $ssoUser ): ?Authenticatable
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        // First, try to find by SSO identity
        $identity = SsoIdentity::byIdpUserId(
            $ssoUser->getIdpId(),
            $ssoUser->getId(),
        )->first();

        if ( $identity ) {
            // Update attributes
            $identity->updateAttributes( $ssoUser->getAttributes() );
            $identity->recordAuthentication( $ssoUser->getSessionIndex() );

            return $identity->user;
        }

        // Try to find existing user by email
        $user = null;
        if ( $ssoUser->hasEmail() ) {
            $user = $userModel::where( 'email', $ssoUser->getEmail() )->first();
        }

        // JIT provisioning if user not found
        if ( null === $user && config( 'artisanpack.security-advanced-auth.sso.jit_provisioning', true ) ) {
            $user = $this->createUserFromSso( $ssoUser );
        }

        if ( null === $user ) {
            return null;
        }

        // Link the SSO identity
        $this->linkIdentity( $user, $ssoUser );

        return $user;
    }

    /**
     * Link an SSO identity to a user.
     */
    public function linkIdentity( Authenticatable $user, SsoUser $ssoUser ): SsoIdentity
    {
        if ( ! method_exists( $user, 'linkSsoIdentity' ) ) {
            throw new RuntimeException( 'User model must implement linkSsoIdentity method. Add the HasSsoIdentities trait.' );
        }

        return $user->linkSsoIdentity(
            $ssoUser->getIdpId(),
            $ssoUser->getId(),
            $ssoUser->getNameId(),
            $ssoUser->getAttributes(),
            $ssoUser->getSessionIndex(),
        );
    }

    /**
     * Unlink an SSO identity from a user.
     */
    public function unlinkIdentity( Authenticatable $user, string $idpId ): bool
    {
        if ( ! method_exists( $user, 'unlinkSsoIdentity' ) ) {
            throw new RuntimeException( 'User model must implement unlinkSsoIdentity method. Add the HasSsoIdentities trait.' );
        }

        return $user->unlinkSsoIdentity( $idpId );
    }

    /**
     * Update user attributes from SSO on login.
     */
    public function updateUserAttributes( Authenticatable $user, SsoUser $ssoUser ): void
    {
        if ( ! config( 'artisanpack.security-advanced-auth.sso.update_on_login', true ) ) {
            return;
        }

        $updated = false;

        if ( $ssoUser->getName() && $user->name !== $ssoUser->getName() ) {
            $user->name = $ssoUser->getName();
            $updated    = true;
        }

        if ( $updated ) {
            $user->save();
        }
    }

    /**
     * Validate an SSO configuration.
     *
     * @return array<string, string>
     */
    public function validateConfiguration( string $slug ): array
    {
        $provider = $this->provider( $slug );

        return $provider->validateConfiguration();
    }

    /**
     * Extend the provider map with a custom provider.
     *
     * @param  class-string<SsoProviderInterface>  $providerClass
     */
    public function extend( string $type, string $providerClass ): void
    {
        $this->providerMap[ $type ] = $providerClass;
    }

    /**
     * Get session logout options for single logout.
     *
     * @return array{name_id: ?string, session_index: ?string}
     */
    public function getLogoutOptions( Authenticatable $user, string $idpId ): array
    {
        $identity = $user->getSsoIdentity( $idpId );

        return [
            'name_id'       => $identity?->name_id,
            'session_index' => $identity?->session_index,
        ];
    }

    /**
     * Create a provider instance for a configuration.
     */
    protected function createProvider( SsoConfiguration $configuration ): SsoProviderInterface
    {
        $providerClass = $this->providerMap[ $configuration->type ] ?? null;

        if ( ! $providerClass ) {
            throw new InvalidArgumentException( "Unknown SSO provider type: {$configuration->type}" );
        }

        /** @var SsoProviderInterface $provider */
        $provider = new $providerClass;

        return $provider->configure( $configuration );
    }

    /**
     * Create a new user from SSO data (JIT provisioning).
     */
    protected function createUserFromSso( SsoUser $ssoUser ): Authenticatable
    {
        $userModel = config( 'auth.providers.users.model', 'App\\Models\\User' );

        $userData = [
            'email'             => $ssoUser->getEmail(),
            'name'              => $ssoUser->getName() ?? $ssoUser->getEmail(),
            'email_verified_at' => now(), // SSO users are pre-verified
        ];

        $user = $userModel::create( $userData );

        // Assign default role if configured
        $defaultRole = config( 'artisanpack.security-advanced-auth.sso.default_role' );
        if ( $defaultRole && method_exists( $user, 'assignRole' ) ) {
            $user->assignRole( $defaultRole);
        }

        return $user;
    }
}
