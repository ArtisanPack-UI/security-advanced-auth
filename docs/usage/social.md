---
title: Social Authentication
---

# Social Authentication

`SocialAuthManager` (363 lines) handles OAuth-based social login. 8 providers ship out of the box.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/auth/social/{provider}/redirect` | Begin OAuth flow |
| GET | `/auth/social/{provider}/callback` | OAuth callback |
| POST | `/auth/social/{provider}/unlink` | Unlink (requires auth) |

## Shipped providers

- `apple` — Sign in with Apple
- `facebook` — Facebook Login
- `github` — GitHub
- `google` — Google
- `linkedin` — LinkedIn
- `microsoft` — Microsoft / Azure AD personal
- `oidc` (`GenericOidcProvider`) — any OIDC provider
- (Custom — extend `AbstractOAuth2Provider` or `AbstractOidcProvider`)

## Registering a provider

```php
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\SocialAuthManager;

// In a service provider's boot()
app( SocialAuthManager::class )->registerProvider( 'google', [
    'client_id'     => env('GOOGLE_CLIENT_ID'),
    'client_secret' => env('GOOGLE_CLIENT_SECRET'),
    'redirect_uri'  => route('security-advanced-auth.social.callback', ['provider' => 'google']),
    'scopes'        => ['openid', 'email', 'profile'],
] );
```

Repeat per provider. Only registered providers respond to the callback routes — unregistered providers throw `RuntimeException`.

## Linking flow

The bundled `SocialAuthController::callback()`:

1. Validates the OAuth `state` parameter (CSRF).
2. Exchanges the `code` for an access token.
3. Fetches the user info from the provider.
4. If `email_domains` is configured and the user's email domain isn't on the list, rejects.
5. Either:
   - Logs in an existing user (if a `SocialIdentity` matches the provider's user ID), or
   - Creates a new user and links a fresh `SocialIdentity`.
6. Redirects to `config('artisanpack.security-advanced-auth.social.redirect_after_login')`.

## Linking to an existing account

For "connect Google" flows on an existing user's settings page, the `SocialAccountsManager` Livewire component handles the UX. Internally:

```php
$socialUser = $manager->callback( $provider, $code, $state );
$manager->linkIdentity( $user, $socialUser, $tokens );
```

## Unlinking

The Livewire component handles unlinking, or call directly:

```php
$manager->unlinkIdentity( $user, $provider );
```

Refuses to unlink the user's only authentication method — they'd be locked out.

## Email domain restriction

To restrict social login to users from specific domains (e.g. only `@mycompany.com`):

```php
'social' => [
    'allowed_email_domains' => ['mycompany.com', 'subsidiary.com'],
],
```

`null` (default) allows any domain.

## Token refresh

```php
$manager->refreshTokens( $socialIdentity );
```

For providers that issue refresh tokens (Google, Microsoft, Facebook), this refreshes the access token using the stored refresh token.

## Custom providers

Implement `SocialProviderInterface` (or extend `AbstractOAuth2Provider` / `AbstractOidcProvider`) and register your class — see [Custom social providers](../advanced/custom-social-providers.md).
