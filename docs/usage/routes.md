---
title: Routes
---

# Routes

`routes/auth.php` registers 12 endpoints across three groups: social OAuth, SSO, and WebAuthn. Configurable prefix + per-group middleware.

## Social OAuth

| Method | Path | Name | Purpose |
|---|---|---|---|
| GET | `/auth/social/{provider}/redirect` | `security-advanced-auth.social.redirect` | Begin OAuth flow |
| GET | `/auth/social/{provider}/callback` | `security-advanced-auth.social.callback` | OAuth callback |
| POST | `/auth/social/{provider}/unlink` | `security-advanced-auth.social.unlink` | Unlink (requires `auth`) |

Default middleware: `['web']`. Override:

```php
'routes' => ['social' => ['middleware' => ['web', 'throttle:social-auth']]],
```

## SSO (SAML / OIDC / LDAP)

| Method | Path | Name |
|---|---|---|
| GET | `/auth/sso/{slug}/login` | `security-advanced-auth.sso.login` |
| GET / POST | `/auth/sso/{slug}/callback` | `security-advanced-auth.sso.callback` |
| POST | `/auth/sso/{slug}/logout` | `security-advanced-auth.sso.logout` |
| GET | `/auth/sso/{slug}/logout/callback` | `security-advanced-auth.sso.logout.callback` |
| GET | `/auth/sso/{slug}/metadata` | `security-advanced-auth.sso.metadata` |

GET + POST on `callback` covers OIDC (GET, auth code flow) and SAML (POST, ACS).

> **CSRF note**: SAML ACS endpoints are POST-from-IdP — your CSRF middleware will reject them unless excluded. Add the path to `VerifyCsrfToken::$except` or use a route group that opts out of CSRF.

## WebAuthn

| Method | Path | Name |
|---|---|---|
| POST | `/auth/webauthn/register/options` | `security-advanced-auth.webauthn.register.options` |
| POST | `/auth/webauthn/register/verify` | `security-advanced-auth.webauthn.register.verify` |
| POST | `/auth/webauthn/authenticate/options` | `security-advanced-auth.webauthn.authenticate.options` |
| POST | `/auth/webauthn/authenticate/verify` | `security-advanced-auth.webauthn.authenticate.verify` |

Default middleware: `['api']`. These are JSON endpoints called by the host app's JS, not full pages.

## Customizing the prefix

```php
'routes' => ['prefix' => 'security'],
```

Changes the base prefix from `auth` to `security`. So URLs become `/security/social/google/redirect` etc.

## Disabling routes wholesale

```php
'routes' => ['enabled' => false],
```

The whole file stops loading. You can then wire your own controllers — call the managers directly:

```php
Route::get('/my-custom-google-redirect', function () {
    $url = app(SocialAuthManager::class)->redirect('google');
    return redirect()->away($url);
});
```

## Generating URLs

Always use named routes for callback URIs you register with the IdP / OAuth provider:

```php
$callbackUrl = route('security-advanced-auth.social.callback', ['provider' => 'google']);
$ssoMetadataUrl = route('security-advanced-auth.sso.metadata', ['slug' => 'corp-saml']);
```

Don't hard-code paths — the prefix is configurable and may differ per environment.
