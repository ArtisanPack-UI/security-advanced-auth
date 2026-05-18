---
title: Custom Social Providers
---

# Custom Social Providers

Add OAuth providers beyond the 8 shipped (Apple, Facebook, GitHub, Google, LinkedIn, Microsoft, generic OIDC, generic OAuth2).

## Extending an abstract base

Most custom providers can extend `AbstractOAuth2Provider` or `AbstractOidcProvider`:

```php
namespace App\Auth\Social;

use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\Providers\AbstractOAuth2Provider;

class StripeProvider extends AbstractOAuth2Provider
{
    protected string $name = 'stripe';

    protected function getAuthorizationUrl(): string
    {
        return 'https://connect.stripe.com/oauth/authorize';
    }

    protected function getTokenUrl(): string
    {
        return 'https://connect.stripe.com/oauth/token';
    }

    protected function getUserInfoUrl(): string
    {
        return 'https://api.stripe.com/v1/account';
    }

    protected function mapUserInfo( array $data ): array
    {
        return [
            'id'    => $data['id'],
            'email' => $data['email'] ?? null,
            'name'  => $data['business_profile']['name'] ?? null,
        ];
    }
}
```

The base class handles state validation, token exchange, and the user-info request — you provide the per-provider URLs and the user-info mapping.

## Registering

```php
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Social\SocialAuthManager;
use App\Auth\Social\StripeProvider;

$this->app->afterResolving( SocialAuthManager::class, function ( SocialAuthManager $manager ): void {
    $manager->extend( 'stripe', StripeProvider::class );
} );
```

Now usable like any shipped provider:

```php
$manager->registerProvider( 'stripe', [
    'client_id'     => env('STRIPE_CLIENT_ID'),
    'client_secret' => env('STRIPE_CLIENT_SECRET'),
    'redirect_uri'  => route('security-advanced-auth.social.callback', ['provider' => 'stripe']),
] );
```

URLs: `/auth/social/stripe/redirect` and `/auth/social/stripe/callback`.

## OIDC-compliant providers

For providers that follow OIDC strictly, extend `AbstractOidcProvider` — you only need to supply the discovery URL:

```php
class AuthZeroProvider extends AbstractOidcProvider
{
    protected string $name = 'auth0';

    protected function getDiscoveryUrl(): string
    {
        return "https://{$this->config['domain']}/.well-known/openid-configuration";
    }
}
```

The base class fetches the discovery document and configures itself from it.

## Implementing from scratch

For providers that don't fit OAuth2 / OIDC patterns, implement `SocialProviderInterface` directly:

```php
namespace ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts;

interface SocialProviderInterface
{
    public function getName(): string;
    public function getRedirectUrl( array $options = [] ): string;
    public function handleCallback( string $code, string $state ): SocialUser;
    public function refreshToken( string $refreshToken ): array;
}
```

## Conventions

- **Validate state.** OAuth state is your CSRF defense — every callback handler must verify it matches what `getRedirectUrl()` stored. The abstract bases do this automatically.
- **Map fields to a stable shape.** `SocialUser` has `id`, `email`, `name`, `avatar`, plus a free-form `raw` array. Always populate `id` (provider's stable user identifier); other fields are best-effort.
- **Be resilient to user-info changes.** Providers occasionally restructure their user-info responses. Use null-safe access and `??` defaults in your `mapUserInfo()` implementation.
