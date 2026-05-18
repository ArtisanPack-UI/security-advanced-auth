---
title: Custom SSO Providers
---

# Custom SSO Providers

`SsoManager` itself is concrete — what's pluggable is the per-type implementation. The shipped `SamlServiceProvider`, `OidcClient`, and `LdapAuthenticator` are configuration-driven wrappers around external libraries. To swap in your own library or a custom protocol, register a new type.

## Adding a type

```php
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Sso\SsoManager;

$this->app->afterResolving( SsoManager::class, function ( SsoManager $manager ): void {
    $manager->extend( 'kerberos', \App\Auth\Sso\KerberosProvider::class );
} );
```

The provider class must implement `SsoProviderInterface`:

```php
interface SsoProviderInterface
{
    public function getName(): string;
    public function getLoginUrl( SsoConfiguration $config, array $options = [] ): string;
    public function handleCallback( SsoConfiguration $config, Request $request ): SsoUser;
    public function getLogoutUrl( SsoConfiguration $config, array $options = [] ): ?string;
    public function handleLogout( SsoConfiguration $config, Request $request ): bool;
    public function getMetadata( SsoConfiguration $config ): ?string;
}
```

## Configurable IdP

Each IdP is an `SsoConfiguration` row with `type`, `slug`, and a free-form `config` JSON. Your provider class reads the `config` to know IdP-specific details (endpoints, certificates, secrets).

```php
SsoConfiguration::create([
    'slug'   => 'corp-kerberos',
    'name'   => 'Corporate Kerberos',
    'type'   => 'kerberos',
    'config' => [
        'realm'   => 'CORP.EXAMPLE.COM',
        'kdc'     => 'krb.corp.example.com',
        // ... whatever your provider needs
    ],
    'is_enabled' => true,
]);
```

Login URL: `/auth/sso/corp-kerberos/login` automatically routes through your `KerberosProvider`.

## Bring-your-own SAML library

The shipped `SamlServiceProvider` is intentionally light. To use `onelogin/php-saml` (or any other SAML library):

```php
namespace App\Auth\Sso;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts\SsoProviderInterface;
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Sso\SsoUser;
use ArtisanPackUI\SecurityAdvancedAuth\Models\SsoConfiguration;
use Illuminate\Http\Request;
use OneLogin\Saml2\Auth as Saml2Auth;

class OneLoginSamlProvider implements SsoProviderInterface
{
    public function getName(): string { return 'saml'; }

    public function handleCallback( SsoConfiguration $config, Request $request ): SsoUser
    {
        $auth = new Saml2Auth( $config->config );
        $auth->processResponse();

        if ( ! $auth->isAuthenticated() ) {
            throw new \RuntimeException( 'SAML authentication failed: ' . implode( ', ', $auth->getErrors() ) );
        }

        return new SsoUser(
            id: $auth->getNameId(),
            email: $auth->getAttribute('email')[0] ?? null,
            attributes: $auth->getAttributes(),
        );
    }

    // ... other interface methods
}
```

Register it as the new `saml` type (replaces the shipped one for that slug):

```php
$manager->extend( 'saml', OneLoginSamlProvider::class );
```

## Multiple IdPs of the same type

The `slug` identifies the IdP, not the type. You can have 5 OIDC IdPs (`okta`, `auth0`, `azure-ad`, `keycloak`, `custom-oidc`) all using the same `OidcClient` provider — each with its own `SsoConfiguration` row carrying different config.

The `slug` becomes the URL path: `/auth/sso/okta/login` vs `/auth/sso/auth0/login`.

## Bypassing the bundled controllers

If your SSO flow doesn't fit the standard redirect-callback pattern, disable the routes and wire your own controllers that call the manager directly:

```php
$loginUrl = app(SsoManager::class)->login('corp-okta');
return redirect()->away($loginUrl);
```
