<?php

/**
 * LinkedInProvider social OAuth provider.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAdvancedAuth
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\Providers;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\SocialUser;

class LinkedInProvider extends AbstractOidcProvider
{
    /**
     * Get the provider name.
     */
    public function getName(): string
    {
        return 'linkedin';
    }

    /**
     * Get the default scopes.
     *
     * @return array<string>
     */
    public function getDefaultScopes(): array
    {
        return ['openid', 'profile', 'email'];
    }

    /**
     * Get the OIDC issuer URL.
     *
     * LinkedIn's issuer in the ID token is 'https://www.linkedin.com'
     * (not the /oauth path used for the discovery document).
     */
    protected function getIssuerUrl(): string
    {
        return 'https://www.linkedin.com';
    }

    /**
     * Get the discovery document URL.
     */
    protected function getDiscoveryUrl(): string
    {
        return 'https://www.linkedin.com/oauth/.well-known/openid-configuration';
    }

    /**
     * Map the provider's user data to a SocialUser.
     *
     * @param  array<string, mixed>  $data
     */
    protected function mapUserData( array $data ): SocialUser
    {
        return new SocialUser(
            id: (string) $data['sub'],
            provider: $this->getName(),
            email: $data['email'] ?? null,
            name: $data['name'] ?? null,
            firstName: $data['given_name'] ?? null,
            lastName: $data['family_name'] ?? null,
            avatar: $data['picture'] ?? null,
            nickname: null,
            scopes: $this->config['scopes'] ?? $this->getDefaultScopes(),
            rawData: $data,
        );
    }
}
