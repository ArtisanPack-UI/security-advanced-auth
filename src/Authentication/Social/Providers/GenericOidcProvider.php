<?php

/**
 * GenericOidcProvider social OAuth provider.
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
use InvalidArgumentException;
use RuntimeException;

class GenericOidcProvider extends AbstractOidcProvider
{
    /**
     * Get the provider name.
     */
    public function getName(): string
    {
        return $this->config['name'] ?? 'oidc';
    }

    /**
     * Get the default scopes.
     *
     * @return array<string>
     */
    public function getDefaultScopes(): array
    {
        return $this->config['scopes'] ?? ['openid', 'profile', 'email'];
    }

    /**
     * Create a generic OIDC provider from configuration.
     *
     * @param  array<string, mixed>  $config
     */
    public static function fromConfig( array $config ): self
    {
        if ( empty( $config['issuer_url'] ) ) {
            throw new InvalidArgumentException( 'issuer_url is required for generic OIDC provider' );
        }

        if ( empty( $config['client_id'] ) ) {
            throw new InvalidArgumentException( 'client_id is required for generic OIDC provider' );
        }

        if ( empty( $config['client_secret'] ) ) {
            throw new InvalidArgumentException( 'client_secret is required for generic OIDC provider' );
        }

        return new self( $config );
    }

    /**
     * Get the OIDC issuer URL.
     */
    protected function getIssuerUrl(): string
    {
        if ( empty( $this->config['issuer_url'] ) ) {
            throw new RuntimeException( 'Issuer URL is required for generic OIDC provider' );
        }

        return $this->config['issuer_url'];
    }

    /**
     * Map the provider's user data to a SocialUser.
     *
     * @param  array<string, mixed>  $data
     */
    protected function mapUserData( array $data ): SocialUser
    {
        $mapping    = $this->config['attribute_mapping'] ?? [];
        $idKey      = $mapping['id'] ?? 'sub';
        $externalId = (string) ( $data[ $idKey ] ?? $data['sub'] ?? '' );

        if ( '' === $externalId ) {
            throw new RuntimeException( 'OIDC subject identifier is missing.' );
        }

        return new SocialUser(
            id: $externalId,
            provider: $this->getName(),
            email: $data[ $mapping['email'] ?? 'email' ] ?? null,
            name: $data[ $mapping['name'] ?? 'name' ] ?? null,
            firstName: $data[ $mapping['given_name'] ?? 'given_name' ] ?? null,
            lastName: $data[ $mapping['family_name'] ?? 'family_name' ] ?? null,
            avatar: $data[ $mapping['picture'] ?? 'picture' ] ?? null,
            nickname: $data[ $mapping['nickname'] ?? 'preferred_username' ] ?? null,
            scopes: $this->config['scopes'] ?? $this->getDefaultScopes(),
            rawData: $data,
        );
    }
}
