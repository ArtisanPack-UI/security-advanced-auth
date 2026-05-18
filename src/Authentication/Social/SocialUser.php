<?php

/**
 * SocialUser social authentication class.
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

use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;

class SocialUser implements Arrayable, JsonSerializable
{
    /**
     * Create a new social user instance.
     *
     * @param  array<string>  $scopes
     * @param  array<string, mixed>  $rawData
     */
    public function __construct(
        protected string $id,
        protected string $provider,
        protected ?string $email = null,
        protected ?string $name = null,
        protected ?string $firstName = null,
        protected ?string $lastName = null,
        protected ?string $avatar = null,
        protected ?string $nickname = null,
        protected array $scopes = [],
        protected array $rawData = [],
    ) {
    }

    /**
     * Get the user's provider ID.
     */
    public function getId(): string
    {
        return $this->id;
    }

    /**
     * Get the provider name.
     */
    public function getProvider(): string
    {
        return $this->provider;
    }

    /**
     * Get the user's email.
     */
    public function getEmail(): ?string
    {
        return $this->email;
    }

    /**
     * Get the user's full name.
     */
    public function getName(): ?string
    {
        return $this->name;
    }

    /**
     * Get the user's first name.
     */
    public function getFirstName(): ?string
    {
        return $this->firstName;
    }

    /**
     * Get the user's last name.
     */
    public function getLastName(): ?string
    {
        return $this->lastName;
    }

    /**
     * Get the user's avatar URL.
     */
    public function getAvatar(): ?string
    {
        return $this->avatar;
    }

    /**
     * Get the user's nickname/username.
     */
    public function getNickname(): ?string
    {
        return $this->nickname;
    }

    /**
     * Get the authorized scopes.
     *
     * @return array<string>
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * Get the raw data from the provider.
     *
     * @return array<string, mixed>
     */
    public function getRawData(): array
    {
        return $this->rawData;
    }

    /**
     * Get a specific raw data value.
     */
    public function getRaw( string $key, mixed $default = null ): mixed
    {
        return data_get( $this->rawData, $key, $default );
    }

    /**
     * Check if the user has an email.
     */
    public function hasEmail(): bool
    {
        return null !== $this->email && '' !== $this->email;
    }

    /**
     * Check if the email is verified (if provider supports it).
     */
    public function isEmailVerified(): bool
    {
        return (bool) $this->getRaw( 'email_verified', false );
    }

    /**
     * Get the instance as an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id'         => $this->id,
            'provider'   => $this->provider,
            'email'      => $this->email,
            'name'       => $this->name,
            'first_name' => $this->firstName,
            'last_name'  => $this->lastName,
            'avatar'     => $this->avatar,
            'nickname'   => $this->nickname,
            'scopes'     => $this->scopes,
        ];
    }

    /**
     * Specify data which should be serialized to JSON.
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Create a SocialUser from an array.
     *
     * @param  array<string, mixed>  $data
     */
    public static function fromArray( string $provider, array $data ): self
    {
        return new self(
            id: (string) ( $data['id'] ?? $data['sub'] ?? '' ),
            provider: $provider,
            email: $data['email'] ?? null,
            name: $data['name'] ?? null,
            firstName: $data['given_name'] ?? $data['first_name'] ?? null,
            lastName: $data['family_name'] ?? $data['last_name'] ?? null,
            avatar: $data['picture'] ?? $data['avatar_url'] ?? $data['avatar'] ?? null,
            nickname: $data['nickname'] ?? $data['login'] ?? $data['username'] ?? null,
            scopes: $data['scopes'] ?? [],
            rawData: $data,
        );
    }
}
