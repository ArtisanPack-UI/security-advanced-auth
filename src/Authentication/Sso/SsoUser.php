<?php

/**
 * SsoUser SSO class.
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

use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;

class SsoUser implements Arrayable, JsonSerializable
{
    /**
     * Create a new SSO user instance.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function __construct(
        protected string $id,
        protected string $idpId,
        protected ?string $nameId = null,
        protected ?string $email = null,
        protected ?string $name = null,
        protected ?string $firstName = null,
        protected ?string $lastName = null,
        protected ?string $sessionIndex = null,
        protected array $attributes = [],
    ) {
    }

    /**
     * Get the user's IdP ID.
     */
    public function getId(): string
    {
        return $this->id;
    }

    /**
     * Get the IdP identifier.
     */
    public function getIdpId(): string
    {
        return $this->idpId;
    }

    /**
     * Get the SAML NameID.
     */
    public function getNameId(): ?string
    {
        return $this->nameId;
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
     * Get the session index (for SAML SLO).
     */
    public function getSessionIndex(): ?string
    {
        return $this->sessionIndex;
    }

    /**
     * Get all attributes.
     *
     * @return array<string, mixed>
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    /**
     * Get a specific attribute.
     */
    public function getAttribute( string $key, mixed $default = null ): mixed
    {
        return $this->attributes[ $key ] ?? $default;
    }

    /**
     * Check if the user has an email.
     */
    public function hasEmail(): bool
    {
        return null !== $this->email && '' !== $this->email;
    }

    /**
     * Get the instance as an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id'            => $this->id,
            'idp_id'        => $this->idpId,
            'name_id'       => $this->nameId,
            'email'         => $this->email,
            'name'          => $this->name,
            'first_name'    => $this->firstName,
            'last_name'     => $this->lastName,
            'session_index' => $this->sessionIndex,
            'attributes'    => $this->attributes,
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
}
