---
title: SSO
---

# SSO (SAML / OIDC / LDAP)

`SsoManager` (302 lines) orchestrates SAML 2.0, OIDC, and LDAP IdPs. Each IdP is defined as an `SsoConfiguration` row — DB-driven so admins can add new IdPs at runtime.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/auth/sso/{slug}/login` | Begin login — redirect to IdP |
| GET / POST | `/auth/sso/{slug}/callback` | Receive IdP response (SAML ACS = POST, OIDC code = GET) |
| POST | `/auth/sso/{slug}/logout` | Begin SLO (Single Logout) |
| GET | `/auth/sso/{slug}/logout/callback` | Receive IdP's SLO callback |
| GET | `/auth/sso/{slug}/metadata` | SAML SP metadata (XML) |

## Defining an IdP

```php
use ArtisanPackUI\SecurityAdvancedAuth\Models\SsoConfiguration;

// OIDC
SsoConfiguration::create([
    'slug'       => 'corp-okta',
    'name'       => 'Corporate Okta',
    'type'       => 'oidc',
    'config'     => [
        'discovery_url' => 'https://corp.okta.com/.well-known/openid-configuration',
        'client_id'     => env('OKTA_CLIENT_ID'),
        'client_secret' => env('OKTA_CLIENT_SECRET'),
        'scopes'        => ['openid', 'email', 'profile'],
    ],
    'is_enabled' => true,
    'is_default' => false,
]);

// SAML
SsoConfiguration::create([
    'slug'   => 'corp-saml',
    'name'   => 'Corporate SAML',
    'type'   => 'saml',
    'config' => [
        'idp_entity_id'   => 'https://saml.corp.example.com',
        'idp_sso_url'     => 'https://saml.corp.example.com/sso',
        'idp_certificate' => '-----BEGIN CERTIFICATE-----...',
    ],
    'is_enabled' => true,
]);

// LDAP
SsoConfiguration::create([
    'slug'   => 'corp-ldap',
    'name'   => 'Corporate LDAP',
    'type'   => 'ldap',
    'config' => [
        'host' => 'ldap.corp.example.com',
        'port' => 636,
        'base_dn' => 'dc=corp,dc=example,dc=com',
    ],
    'is_enabled' => true,
]);
```

## Triggering login

```blade
<a href="{{ route('security-advanced-auth.sso.login', ['slug' => 'corp-okta']) }}">
    Sign in with Corporate Okta
</a>
```

The user goes to the IdP, authenticates there, IdP redirects back to `/auth/sso/corp-okta/callback`. The bundled `SsoController` handles user creation / linking and logs the user in.

## Identity linking

When a user signs in via SSO, the `SsoManager::findOrCreateUser()` method:

1. Looks up an `SsoIdentity` matching the IdP's user identifier
2. If found, returns the linked User
3. If not found, creates a new User from the IdP attributes and writes the link

For "link existing account" flows where the user is already signed in, call `linkIdentity( $user, $ssoUser )` directly.

## SAML SP metadata

Your SAML IdP needs your SP metadata to federate. Expose it via the bundled metadata endpoint — `https://your-app.com/auth/sso/{slug}/metadata` returns the XML. Most IdPs (Okta, OneLogin, Azure AD, etc.) accept a URL for SP setup; point them here.

## Single Logout (SLO)

The shipped flow:

1. User clicks "Sign out" in your app.
2. Your logout flow calls `/auth/sso/{slug}/logout`.
3. `SsoController` logs the user out locally and redirects to the IdP's logout URL.
4. After IdP signs the user out, IdP redirects back to `/auth/sso/{slug}/logout/callback`.
5. `SsoController::logoutCallback()` runs your post-logout logic.

Not all SAML IdPs support SLO. For those that don't, calling local logout is sufficient.

## Required SSO libraries

The shipped `SsoManager` is configuration-driven. The actual SAML / OIDC / LDAP protocol handling needs a library — install whichever fits your stack:

- SAML: `simplesamlphp/saml2` or `onelogin/php-saml`
- OIDC: `web-token/jwt-framework` or the OIDC client of your choice
- LDAP: `directorytree/ldaprecord-laravel`

Bind your library's client to the corresponding `SsoProviderInterface` slot — see [Custom SSO providers](../advanced/custom-sso-providers.md).
