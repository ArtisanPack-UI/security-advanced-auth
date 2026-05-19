<?php

/**
 * SamlServiceProvider SAML SSO class.
 *
 * @package    ArtisanPack_UI
 * @subpackage SecurityAdvancedAuth
 *
 * @author     Jacob Martella <support@artisanpackui.dev>
 *
 * @since      1.0.0
 */

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Sso\Saml;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts\SsoProviderInterface;
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Sso\SsoUser;
use ArtisanPackUI\SecurityAdvancedAuth\Models\SsoConfiguration;
use DOMDocument;
use DOMElement;
use DOMXPath;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * SAML 2.0 Service Provider implementation.
 *
 * IMPORTANT SECURITY NOTE: This implementation validates SAML response structure,
 * time conditions, and audience restrictions, but does NOT verify cryptographic
 * signatures on SAML assertions. For production deployments handling sensitive
 * authentication, you should:
 *
 * 1. Use a dedicated SAML library (e.g., onelogin/php-saml, simplesamlphp/simplesamlphp)
 *    that provides full XML signature verification.
 * 2. Ensure `want_assertions_signed` and `want_messages_signed` are enforced.
 * 3. Properly validate the IdP certificate chain.
 *
 * This implementation is suitable for development and testing environments,
 * or when used behind a reverse proxy that handles SAML signature verification.
 */
class SamlServiceProvider implements SsoProviderInterface
{
    /**
     * The SSO configuration.
     */
    protected ?SsoConfiguration $configuration = null;

    /**
     * The parsed IdP settings.
     *
     * @var array<string, mixed>
     */
    protected array $idpSettings = [];

    /**
     * The SP settings.
     *
     * @var array<string, mixed>
     */
    protected array $spSettings = [];

    /**
     * Get the provider type.
     */
    public function getType(): string
    {
        return 'saml';
    }

    /**
     * Configure the provider.
     */
    public function configure( SsoConfiguration $configuration ): self
    {
        $this->configuration = $configuration;
        $this->parseConfiguration();

        return $this;
    }

    /**
     * Get the login URL.
     */
    public function getLoginUrl( array $options = [] ): string
    {
        $samlRequest = $this->buildAuthnRequest();

        $params = [
            'SAMLRequest' => base64_encode( gzdeflate( $samlRequest ) ),
        ];

        // Add RelayState if provided
        if ( ! empty( $options['relay_state'] ) ) {
            $params['RelayState'] = $options['relay_state'];
        }

        return $this->idpSettings['ssoUrl'] . '?' . http_build_query( $params );
    }

    /**
     * Handle the SAML callback (ACS).
     */
    public function handleCallback( Request $request ): SsoUser
    {
        $samlResponse = $request->input( 'SAMLResponse' );

        if ( empty( $samlResponse ) ) {
            throw new RuntimeException( 'No SAML response received' );
        }

        $xml = base64_decode( $samlResponse );

        // Parse and validate the response
        $response = $this->parseResponse( $xml );

        // Extract user data
        return $this->extractUserFromResponse( $response );
    }

    /**
     * Get the logout URL.
     */
    public function getLogoutUrl( array $options = [] ): ?string
    {
        if ( empty( $this->idpSettings['sloUrl'] ) ) {
            return null;
        }

        $logoutRequest = $this->buildLogoutRequest( $options );

        $params = [
            'SAMLRequest' => base64_encode( gzdeflate( $logoutRequest ) ),
        ];

        if ( ! empty( $options['relay_state'] ) ) {
            $params['RelayState'] = $options['relay_state'];
        }

        return $this->idpSettings['sloUrl'] . '?' . http_build_query( $params );
    }

    /**
     * Handle the logout response.
     */
    public function handleLogout( Request $request ): bool
    {
        $samlResponse = $request->input( 'SAMLResponse' );

        if ( empty( $samlResponse ) ) {
            return false;
        }

        try {
            // Parse and validate logout response with XXE protection
            $xml = base64_decode( $samlResponse );
            $dom = $this->loadXmlSecurely( $xml );

            $xpath = new DOMXPath( $dom );
            $xpath->registerNamespace( 'samlp', 'urn:oasis:names:tc:SAML:2.0:protocol' );

            $statusCode = $xpath->query( '//samlp:StatusCode/@Value' )->item( 0 )?->nodeValue;

            return 'urn:oasis:names:tc:SAML:2.0:status:Success' === $statusCode;
        } catch ( Exception ) {
            return false;
        }
    }

    /**
     * Get the SP metadata.
     */
    public function getMetadata(): ?string
    {
        $entityId     = $this->spSettings['entityId'];
        $acsUrl       = $this->spSettings['assertionConsumerServiceUrl'];
        $sloUrl       = $this->spSettings['singleLogoutServiceUrl'];
        $nameIdFormat = $this->spSettings['nameIdFormat'];

        $metadata = <<<XML
<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{$entityId}">
    <md:SPSSODescriptor
        AuthnRequestsSigned="true"
        WantAssertionsSigned="true"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:NameIDFormat>{$nameIdFormat}</md:NameIDFormat>
        <md:AssertionConsumerService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="{$acsUrl}"
            index="0"/>
        <md:SingleLogoutService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="{$sloUrl}"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>
XML;

        return $metadata;
    }

    /**
     * Validate the configuration.
     */
    public function validateConfiguration(): array
    {
        $errors = [];

        if ( empty( $this->idpSettings['entityId'] ) ) {
            $errors['idp_entity_id'] = 'IdP Entity ID is required';
        }

        if ( empty( $this->idpSettings['ssoUrl'] ) ) {
            $errors['idp_sso_url'] = 'IdP SSO URL is required';
        }

        if ( empty( $this->idpSettings['x509cert'] ) ) {
            $errors['idp_certificate'] = 'IdP Certificate is required';
        }

        return $errors;
    }

    /**
     * Map provider attributes.
     */
    public function mapAttributes( array $providerAttributes ): array
    {
        $mapping = $this->configuration->attribute_mapping ?? [];
        $mapped  = [];

        foreach ( $mapping as $localKey => $providerKey ) {
            if ( isset( $providerAttributes[ $providerKey ] ) ) {
                $value               = $providerAttributes[ $providerKey ];
                $mapped[ $localKey ] = is_array( $value ) ? $value[0] : $value;
            }
        }

        return $mapped;
    }

    /**
     * Check if single logout is supported.
     */
    public function supportsSingleLogout(): bool
    {
        return ! empty( $this->idpSettings['sloUrl'] );
    }

    /**
     * Check if JIT provisioning is supported.
     */
    public function supportsJitProvisioning(): bool
    {
        return config( 'artisanpack.security-advanced-auth.sso.jit_provisioning', true );
    }

    /**
     * Parse the configuration into settings.
     */
    protected function parseConfiguration(): void
    {
        $settings = $this->configuration->settings ?? [];

        // IdP settings
        $this->idpSettings = [
            'entityId' => $settings['idp_entity_id'] ?? '',
            'ssoUrl'   => $settings['idp_sso_url'] ?? '',
            'sloUrl'   => $settings['idp_slo_url'] ?? null,
            'x509cert' => $settings['idp_certificate'] ?? $this->configuration->certificate ?? '',
        ];

        // SP settings from global config
        $samlConfig       = config( 'artisanpack.security-advanced-auth.sso.saml', [] );
        $this->spSettings = [
            'entityId'                    => $samlConfig['entity_id'] ?? config( 'app.url' ),
            'assertionConsumerServiceUrl' => $this->buildAcsUrl(),
            'singleLogoutServiceUrl'      => $this->buildSloUrl(),
            'x509cert'                    => $samlConfig['certificate'] ?? '',
            'privateKey'                  => $samlConfig['private_key'] ?? '',
            'signRequests'                => $samlConfig['sign_requests'] ?? true,
            'signAssertions'              => $samlConfig['sign_assertions'] ?? true,
            'nameIdFormat'                => $samlConfig['name_id_format'] ?? 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        ];
    }

    /**
     * Build the ACS URL.
     */
    protected function buildAcsUrl(): string
    {
        $baseUrl = config( 'app.url' );
        $slug    = $this->configuration->slug ?? 'saml';

        return "{$baseUrl}/auth/sso/{$slug}/acs";
    }

    /**
     * Build the SLO URL.
     */
    protected function buildSloUrl(): string
    {
        $baseUrl = config( 'app.url' );
        $slug    = $this->configuration->slug ?? 'saml';

        return "{$baseUrl}/auth/sso/{$slug}/logout";
    }

    /**
     * Build the SAML AuthnRequest.
     */
    protected function buildAuthnRequest(): string
    {
        $id           = '_' . Str::uuid()->toString();
        $issueInstant = gmdate( 'Y-m-d\TH:i:s\Z' );

        $authnRequest = <<<XML
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{$id}"
    Version="2.0"
    IssueInstant="{$issueInstant}"
    Destination="{$this->idpSettings['ssoUrl']}"
    AssertionConsumerServiceURL="{$this->spSettings['assertionConsumerServiceUrl']}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>{$this->spSettings['entityId']}</saml:Issuer>
    <samlp:NameIDPolicy
        Format="{$this->spSettings['nameIdFormat']}"
        AllowCreate="true"/>
</samlp:AuthnRequest>
XML;

        return $authnRequest;
    }

    /**
     * Safely load XML with XXE protection.
     *
     * @throws RuntimeException if XML parsing fails
     */
    protected function loadXmlSecurely( string $xml ): DOMDocument
    {
        $previousInternalErrors = libxml_use_internal_errors( true );

        try {
            $dom                     = new DOMDocument;
            $dom->preserveWhiteSpace = false;

            // LIBXML_NONET prevents network access during parsing
            // Remove LIBXML_NOENT as it enables entity substitution
            $options = LIBXML_NONET;

            if ( ! $dom->loadXML( $xml, $options ) ) {
                $errors = libxml_get_errors();
                libxml_clear_errors();
                $errorMsg = ! empty( $errors ) ? $errors[0]->message : 'Unknown XML parsing error';
                throw new RuntimeException( 'Failed to parse XML: ' . trim( $errorMsg ) );
            }

            return $dom;
        } finally {
            libxml_use_internal_errors( $previousInternalErrors );
        }
    }

    /**
     * Parse the SAML response.
     *
     * @return array<string, mixed>
     */
    protected function parseResponse( string $xml ): array
    {
        $dom = $this->loadXmlSecurely( $xml );

        $xpath = new DOMXPath( $dom );
        $xpath->registerNamespace( 'saml', 'urn:oasis:names:tc:SAML:2.0:assertion' );
        $xpath->registerNamespace( 'samlp', 'urn:oasis:names:tc:SAML:2.0:protocol' );

        // Check status
        $statusCode = $xpath->query( '//samlp:StatusCode/@Value' )->item( 0 )?->nodeValue;
        if ( 'urn:oasis:names:tc:SAML:2.0:status:Success' !== $statusCode ) {
            throw new RuntimeException( 'SAML authentication failed: ' . $statusCode );
        }

        // Validate time conditions
        $this->validateConditions( $xpath );

        // Validate audience restriction if configured
        $this->validateAudience( $xpath );

        // Extract assertion data
        $nameId       = $xpath->query( '//saml:NameID' )->item( 0 )?->nodeValue;
        $sessionIndex = $xpath->query( '//saml:AuthnStatement/@SessionIndex' )->item( 0 )?->nodeValue;

        // Extract attributes
        $attributes     = [];
        $attributeNodes = $xpath->query( '//saml:Attribute' );

        foreach ( $attributeNodes as $node ) {
            $name            = $node->getAttribute( 'Name' );
            $values          = $xpath->query( 'saml:AttributeValue', $node );
            $attributeValues = [];

            foreach ( $values as $value ) {
                $attributeValues[] = $value->nodeValue;
            }

            $attributes[ $name ] = 1 === count( $attributeValues ) ? $attributeValues[0] : $attributeValues;
        }

        return [
            'name_id'       => $nameId,
            'session_index' => $sessionIndex,
            'attributes'    => $attributes,
        ];
    }

    /**
     * Validate SAML assertion time conditions.
     *
     * @throws RuntimeException if conditions are invalid
     */
    protected function validateConditions( DOMXPath $xpath ): void
    {
        $conditions = $xpath->query( '//saml:Conditions' )->item( 0 );

        if ( ! $conditions instanceof DOMElement ) {
            return; // No conditions to validate
        }

        $now                = time();
        $clockSkewAllowance = 300; // 5 minutes tolerance for clock skew

        // Validate NotBefore
        $notBefore = $conditions->getAttribute( 'NotBefore' );
        if ( $notBefore ) {
            $notBeforeTime = strtotime( $notBefore );
            if ( false !== $notBeforeTime && ( $now + $clockSkewAllowance ) < $notBeforeTime ) {
                throw new RuntimeException( 'SAML assertion is not yet valid' );
            }
        }

        // Validate NotOnOrAfter
        $notOnOrAfter = $conditions->getAttribute( 'NotOnOrAfter' );
        if ( $notOnOrAfter ) {
            $notOnOrAfterTime = strtotime( $notOnOrAfter );
            if ( false !== $notOnOrAfterTime && ( $now - $clockSkewAllowance ) >= $notOnOrAfterTime ) {
                throw new RuntimeException( 'SAML assertion has expired' );
            }
        }
    }

    /**
     * Validate SAML audience restriction.
     *
     * @throws RuntimeException if audience is invalid
     */
    protected function validateAudience( DOMXPath $xpath ): void
    {
        $audiences = $xpath->query( '//saml:AudienceRestriction/saml:Audience' );

        if ( 0 === $audiences->length ) {
            return; // No audience restriction to validate
        }

        $expectedAudience = $this->spSettings['entityId'];
        $audienceValid    = false;

        foreach ( $audiences as $audience ) {
            if ( $audience->nodeValue === $expectedAudience ) {
                $audienceValid = true;
                break;
            }
        }

        if ( ! $audienceValid ) {
            throw new RuntimeException( 'SAML assertion audience does not match SP entity ID' );
        }
    }

    /**
     * Extract user from SAML response.
     *
     * @param  array<string, mixed>  $response
     */
    protected function extractUserFromResponse( array $response ): SsoUser
    {
        $attributes = $response['attributes'];
        $mapping    = $this->configuration->attribute_mapping ?? [];

        // Apply attribute mapping
        $email     = $this->getMappedAttribute( $attributes, $mapping, 'email' );
        $name      = $this->getMappedAttribute( $attributes, $mapping, 'name' );
        $firstName = $this->getMappedAttribute( $attributes, $mapping, 'first_name' );
        $lastName  = $this->getMappedAttribute( $attributes, $mapping, 'last_name' );

        // Generate user ID from NameID or email
        $userId = $response['name_id'] ?? $email ?? Str::uuid()->toString();

        return new SsoUser(
            id: $userId,
            idpId: $this->configuration->slug,
            nameId: $response['name_id'],
            email: $email,
            name: $name ?: trim( ( $firstName ?? '' ) . ' ' . ( $lastName ?? '' ) ) ?: null,
            firstName: $firstName,
            lastName: $lastName,
            sessionIndex: $response['session_index'],
            attributes: $attributes,
        );
    }

    /**
     * Get a mapped attribute value.
     *
     * @param  array<string, mixed>  $attributes
     * @param  array<string, string>  $mapping
     */
    protected function getMappedAttribute( array $attributes, array $mapping, string $key ): ?string
    {
        $attributeName = $mapping[ $key ] ?? null;

        if ( null === $attributeName ) {
            // Try common attribute names
            $commonNames = $this->getCommonAttributeNames( $key );
            foreach ( $commonNames as $name ) {
                if ( isset( $attributes[ $name ] ) ) {
                    return is_array( $attributes[ $name ] ) ? $attributes[ $name ][0] : $attributes[ $name ];
                }
            }

            return null;
        }

        $value = $attributes[ $attributeName ] ?? null;

        return is_array( $value ) ? $value[0] : $value;
    }

    /**
     * Get common attribute names for a key.
     *
     * @return array<string>
     */
    protected function getCommonAttributeNames( string $key ): array
    {
        return match ( $key ) {
            'email' => [
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
                'email',
                'mail',
                'Email',
            ],
            'name' => [
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
                'name',
                'displayName',
                'cn',
            ],
            'first_name' => [
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
                'givenName',
                'firstName',
                'first_name',
            ],
            'last_name' => [
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
                'surname',
                'lastName',
                'last_name',
                'sn',
            ],
            default => [],
        };
    }

    /**
     * Build the SAML LogoutRequest.
     *
     * @param  array<string, mixed>  $options
     */
    protected function buildLogoutRequest( array $options ): string
    {
        $id           = '_' . Str::uuid()->toString();
        $issueInstant = gmdate( 'Y-m-d\TH:i:s\Z' );
        $nameId       = $options['name_id'] ?? '';
        $sessionIndex = $options['session_index'] ?? '';

        $logoutRequest = <<<XML
<samlp:LogoutRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{$id}"
    Version="2.0"
    IssueInstant="{$issueInstant}"
    Destination="{$this->idpSettings['sloUrl']}">
    <saml:Issuer>{$this->spSettings['entityId']}</saml:Issuer>
    <saml:NameID>{$nameId}</saml:NameID>
    <samlp:SessionIndex>{$sessionIndex}</samlp:SessionIndex>
</samlp:LogoutRequest>
XML;

        return $logoutRequest;
    }
}
