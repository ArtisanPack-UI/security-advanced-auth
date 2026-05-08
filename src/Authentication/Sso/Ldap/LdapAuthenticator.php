<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Sso\Ldap;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts\SsoProviderInterface;
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Sso\SsoUser;
use ArtisanPackUI\SecurityAdvancedAuth\Models\SsoConfiguration;
use Exception;
use Illuminate\Http\Request;
use RuntimeException;

class LdapAuthenticator implements SsoProviderInterface
{
    /**
     * The SSO configuration.
     */
    protected ?SsoConfiguration $configuration = null;

    /**
     * The LDAP settings.
     *
     * @var array<string, mixed>
     */
    protected array $settings = [];

    /**
     * The LDAP connection.
     *
     * @var false|\LDAP\Connection
     */
    protected $connection = false;

    /**
     * Destructor - ensure connection is closed.
     */
    public function __destruct()
    {
        $this->disconnect();
    }

    /**
     * Get the provider type.
     */
    public function getType(): string
    {
        return 'ldap';
    }

    /**
     * Configure the provider.
     *
     * @throws RuntimeException If the LDAP extension is not installed
     */
    public function configure( SsoConfiguration $configuration ): self
    {
        if ( ! extension_loaded( 'ldap' ) ) {
            throw new RuntimeException( 'LDAP extension is not installed' );
        }

        $this->configuration = $configuration;
        $this->settings      = $configuration->settings ?? [];

        return $this;
    }

    /**
     * Get the login URL (not applicable for LDAP - returns form URL).
     */
    public function getLoginUrl( array $options = [] ): string
    {
        // LDAP uses form-based authentication, not redirects
        return config( 'app.url' ) . '/auth/sso/' . $this->configuration->slug . '/login';
    }

    /**
     * Handle the callback (authenticate user with username/password).
     */
    public function handleCallback( Request $request ): SsoUser
    {
        $username = $request->input( 'username' );
        $password = $request->input( 'password' );

        if ( empty( $username ) || empty( $password ) ) {
            throw new RuntimeException( 'Username and password are required' );
        }

        // Connect to LDAP
        $this->connect();

        // Authenticate and get user
        return $this->authenticate( $username, $password );
    }

    /**
     * Get the logout URL (not applicable for LDAP).
     */
    public function getLogoutUrl( array $options = [] ): ?string
    {
        return null;
    }

    /**
     * Handle logout (just return true for LDAP).
     */
    public function handleLogout( Request $request ): bool
    {
        return true;
    }

    /**
     * Get metadata (not applicable for LDAP).
     */
    public function getMetadata(): ?string
    {
        return null;
    }

    /**
     * Validate the configuration.
     */
    public function validateConfiguration(): array
    {
        $errors = [];

        $hosts = $this->settings['hosts'] ?? config( 'artisanpack.security-advanced-auth.sso.ldap.hosts' );
        if ( empty( $hosts ) ) {
            $errors['hosts'] = 'LDAP host is required';
        }

        $baseDn = $this->settings['base_dn'] ?? config( 'artisanpack.security-advanced-auth.sso.ldap.base_dn' );
        if ( empty( $baseDn ) ) {
            $errors['base_dn'] = 'Base DN is required';
        }

        // Try to connect
        if ( empty( $errors ) ) {
            try {
                $this->connect();
            } catch ( Exception $e ) {
                $errors['connection'] = 'Failed to connect: ' . $e->getMessage();
            } finally {
                // Always clean up the connection after validation
                if ( false !== $this->connection ) {
                    $this->disconnect();
                }
            }
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
            $attr = strtolower( $providerKey );
            if ( isset( $providerAttributes[ $attr ] ) ) {
                $mapped[ $localKey ] = $providerAttributes[ $attr ];
            }
        }

        return $mapped;
    }

    /**
     * LDAP doesn't support single logout.
     */
    public function supportsSingleLogout(): bool
    {
        return false;
    }

    /**
     * Check if JIT provisioning is supported.
     */
    public function supportsJitProvisioning(): bool
    {
        return config( 'artisanpack.security-advanced-auth.sso.jit_provisioning', true );
    }

    /**
     * Disconnect from LDAP.
     */
    public function disconnect(): void
    {
        if ( $this->connection ) {
            ldap_unbind( $this->connection );
            $this->connection = false;
        }
    }

    /**
     * Connect to LDAP server.
     */
    protected function connect(): void
    {
        $hosts = $this->settings['hosts'] ?? config( 'artisanpack.security-advanced-auth.sso.ldap.hosts' );
        
        if ( empty( $hosts ) ) {
            throw new RuntimeException( 'LDAP host configuration is required' );
        }
        $port = $this->settings['port'] ?? config( 'artisanpack.security-advanced-auth.sso.ldap.port', 389 );
        $host = is_array( $hosts ) ? $hosts[0] : $hosts;

        $ldapUri = ( $this->settings['use_ssl'] ?? false )
            ? "ldaps://{$host}:{$port}"
            : "ldap://{$host}:{$port}";

        $this->connection = ldap_connect( $ldapUri );

        if ( false === $this->connection ) {
            throw new RuntimeException( 'Failed to connect to LDAP server' );
        }

        // Set LDAP options
        ldap_set_option( $this->connection, LDAP_OPT_PROTOCOL_VERSION, 3 );
        ldap_set_option( $this->connection, LDAP_OPT_REFERRALS, 0 );

        // Start TLS if configured
        if ( $this->settings['use_tls'] ?? config( 'artisanpack.security-advanced-auth.sso.ldap.use_tls', false ) ) {
            if ( ! @ldap_start_tls( $this->connection ) ) {
                throw new RuntimeException( 'Failed to start TLS: ' . ldap_error( $this->connection ) );
            }
        }
    }

    /**
     * Authenticate user against LDAP.
     */
    protected function authenticate( string $username, string $password ): SsoUser
    {
        $baseDn     = $this->settings['base_dn'] ?? config( 'artisanpack.security-advanced-auth.sso.ldap.base_dn' );
        $userFilter = $this->settings['user_filter'] ?? '(sAMAccountName={username})';

        // Replace placeholder
        $filter = str_replace( '{username}', ldap_escape( $username, '', LDAP_ESCAPE_FILTER ), $userFilter );

        // Bind with service account first (if configured)
        $serviceUsername = $this->settings['username'] ?? config( 'artisanpack.security-advanced-auth.sso.ldap.username' );
        $servicePassword = $this->settings['password'] ?? config( 'artisanpack.security-advanced-auth.sso.ldap.password' );

        if ( $serviceUsername && $servicePassword ) {
            if ( ! @ldap_bind( $this->connection, $serviceUsername, $servicePassword ) ) {
                throw new RuntimeException( 'Failed to bind with service account: ' . ldap_error( $this->connection ) );
            }
        }

        // Search for user
        $search = @ldap_search( $this->connection, $baseDn, $filter );

        if ( false === $search ) {
            throw new RuntimeException( 'LDAP search failed: ' . ldap_error( $this->connection ) );
        }

        $entries = ldap_get_entries( $this->connection, $search );

        if ( 0 === $entries['count'] ) {
            throw new RuntimeException( 'User not found' );
        }

        $userDn = $entries[0]['dn'];

        // Bind as the user to verify password
        if ( ! @ldap_bind( $this->connection, $userDn, $password ) ) {
            throw new RuntimeException( 'Invalid credentials' );
        }

        // Extract user data
        return $this->extractUser( $entries[0] );
    }

    /**
     * Extract user from LDAP entry.
     *
     * @param  array<string, mixed>  $entry
     */
    protected function extractUser( array $entry ): SsoUser
    {
        $mapping = $this->configuration->attribute_mapping ?? [];

        // Default attribute names for Active Directory
        $defaultMapping = [
            'id'         => 'objectguid',
            'email'      => 'mail',
            'name'       => 'displayname',
            'first_name' => 'givenname',
            'last_name'  => 'sn',
            'username'   => 'samaccountname',
        ];

        $mapping = array_merge( $defaultMapping, $mapping );

        $getId = function () use ( $entry, $mapping ) {
            $idAttr = strtolower( $mapping['id'] );
            if ( isset( $entry[ $idAttr ][0] ) ) {
                // ObjectGUID needs special handling
                if ( 'objectguid' === $idAttr ) {
                    return $this->formatGuid( $entry[ $idAttr ][0] );
                }

                return $entry[ $idAttr ][0];
            }

            return $entry['dn'];
        };

        $getAttribute = function ( $key ) use ( $entry, $mapping ) {
            $attr = strtolower( $mapping[ $key ] ?? $key );

            return $entry[ $attr ][0] ?? null;
        };

        return new SsoUser(
            id: $getId(),
            idpId: $this->configuration->slug,
            nameId: $getAttribute( 'username' ),
            email: $getAttribute( 'email' ),
            name: $getAttribute( 'name' ),
            firstName: $getAttribute( 'first_name' ),
            lastName: $getAttribute( 'last_name' ),
            sessionIndex: null,
            attributes: $this->extractAllAttributes( $entry ),
        );
    }

    /**
     * Extract all attributes from LDAP entry.
     *
     * @param  array<string, mixed>  $entry
     *
     * @return array<string, mixed>
     */
    protected function extractAllAttributes( array $entry ): array
    {
        $attributes = [];

        for ( $i = 0; $i < ( $entry['count'] ?? 0 ); $i++ ) {
            $attrName = $entry[ $i ];
            if ( isset( $entry[ $attrName ] ) ) {
                $values = [];
                for ( $j = 0; $j < $entry[ $attrName ]['count']; $j++ ) {
                    $values[] = $entry[ $attrName ][ $j ];
                }
                $attributes[ $attrName ] = 1 === count( $values ) ? $values[0] : $values;
            }
        }

        return $attributes;
    }

    /**
     * Format a binary GUID to string.
     */
    protected function formatGuid( string $binaryGuid ): string
    {
        $hex = bin2hex( $binaryGuid );

        return sprintf(
            '%s-%s-%s-%s-%s',
            substr( $hex, 6, 2 ) . substr( $hex, 4, 2 ) . substr( $hex, 2, 2 ) . substr( $hex, 0, 2),
            substr( $hex, 10, 2) . substr( $hex, 8, 2),
            substr( $hex, 14, 2) . substr( $hex, 12, 2),
            substr( $hex, 16, 4),
            substr( $hex, 20, 12),
        );
    }
}
