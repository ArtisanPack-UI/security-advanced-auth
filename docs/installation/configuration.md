---
title: Configuration
---

# Configuration

Publish the config:

```bash
php artisan vendor:publish --tag=security-advanced-auth-config
```

Lives at `config/artisanpack/security-advanced-auth.php`.

## `routes`

```php
'routes' => [
    'enabled'  => env('SECURITY_ADVANCED_AUTH_ROUTES_ENABLED', true),
    'prefix'   => env('SECURITY_ADVANCED_AUTH_ROUTES_PREFIX', 'auth'),
    'social'   => ['middleware' => ['web']],
    'sso'      => ['middleware' => ['web']],
    'webauthn' => ['middleware' => ['api']],
],
```

Disable the routes wholesale or per-group, swap the prefix, customize middleware (e.g. add CSRF exemption for the SAML ACS endpoint).

## `webauthn`

```php
'webauthn' => [
    'relying_party' => [
        'id'   => env('WEBAUTHN_RP_ID', parse_url(env('APP_URL'), PHP_URL_HOST)),
        'name' => env('WEBAUTHN_RP_NAME', config('app.name')),
    ],
    'passwordless_enabled'      => true,
    'max_credentials_per_user'  => 10,
],
```

## `social`

```php
'social' => [
    'redirect_after_login' => '/dashboard',
    'allowed_email_domains' => null,   // null = any; or ['example.com', 'mycompany.com']
],
```

Per-provider config (client_id / secret / etc.) is registered via `SocialAuthManager::registerProvider()` from a service provider, not from config — provider credentials are usually per-environment env vars.

## `sso`

```php
'sso' => [
    'redirect_after_login' => '/dashboard',
],
```

Per-IdP config lives in the `sso_configurations` table — DB-driven so it can be edited at runtime via an admin UI.

## `biometric`

```php
'biometric' => [
    'default_provider' => 'webauthn',
],
```

## `device_fingerprint`

```php
'device_fingerprint' => [
    'enabled'                 => true,
    'trust_period'            => 90,   // days a device stays trusted after a successful login
    'auto_trust_after_logins' => null, // or integer N — auto-trust after N successful logins from the same fingerprint
],
```

## `suspicious_activity`

```php
'suspicious_activity' => [
    'enabled'                => true,
    'impossible_travel_kmh'  => 800,
    'datacenter_check'       => true,
    'tor_check'              => true,
    'auto_lock_threshold'    => 'high',  // severity at which to auto-lock the account
],
```
