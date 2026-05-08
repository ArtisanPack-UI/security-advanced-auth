<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\Providers;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\SocialUser;

class MicrosoftProvider extends AbstractOidcProvider
{
    /**
     * The default tenant.
     */
    protected const DEFAULT_TENANT = 'common';

    /**
     * Get the provider name.
     */
    public function getName(): string
    {
        return 'microsoft';
    }

    /**
     * Get the default scopes.
     *
     * @return array<string>
     */
    public function getDefaultScopes(): array
    {
        return ['openid', 'profile', 'email', 'User.Read'];
    }

    /**
     * Check if the user is from a specific tenant.
     */
    public function isFromTenant( SocialUser $user, string $tenant ): bool
    {
        $tid = $user->getRaw( 'tid' );

        return $tid === $tenant;
    }

    /**
     * Get available tenants.
     *
     * @return array<string, string>
     */
    public static function getAvailableTenants(): array
    {
        return [
            'common'        => 'Any Microsoft account (personal and organizational)',
            'organizations' => 'Work or school accounts only',
            'consumers'     => 'Personal Microsoft accounts only',
        ];
    }

    /**
     * Get the tenant.
     */
    protected function getTenant(): string
    {
        return $this->config['tenant'] ?? self::DEFAULT_TENANT;
    }

    /**
     * Get the OIDC issuer URL.
     */
    protected function getIssuerUrl(): string
    {
        return 'https://login.microsoftonline.com/' . $this->getTenant() . '/v2.0';
    }

    /**
     * Get the discovery document URL.
     */
    protected function getDiscoveryUrl(): string
    {
        return 'https://login.microsoftonline.com/' . $this->getTenant() . '/v2.0/.well-known/openid-configuration';
    }

    /**
     * Get additional authorization parameters.
     *
     * @param  array<string, mixed>  $options
     *
     * @return array<string, mixed>
     */
    protected function getAdditionalAuthorizationParams( array $options ): array
    {
        $params = parent::getAdditionalAuthorizationParams( $options );

        // Request offline access for refresh tokens
        $params['prompt'] = $options['prompt'] ?? 'select_account';

        return $params;
    }

    /**
     * Get the user info endpoint (Microsoft Graph API).
     */
    protected function getUserInfoEndpoint(): string
    {
        // Use Microsoft Graph API instead of OIDC userinfo
        return 'https://graph.microsoft.com/v1.0/me';
    }

    /**
     * Map the provider's user data to a SocialUser.
     *
     * @param  array<string, mixed>  $data
     */
    protected function mapUserData( array $data ): SocialUser
    {
        return new SocialUser(
            id: (string) $data['id'],
            provider: $this->getName(),
            email: $data['mail'] ?? $data['userPrincipalName'] ?? null,
            name: $data['displayName'] ?? null,
            firstName: $data['givenName'] ?? null,
            lastName: $data['surname'] ?? null,
            avatar: null, // Microsoft Graph requires separate call for photo
            nickname: $data['userPrincipalName'] ?? null,
            scopes: $this->config['scopes'] ?? $this->getDefaultScopes(),
            rawData: $data,
        );
    }
}
