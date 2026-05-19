---
title: Installation
---

# Installation

## Install via Composer

```bash
composer require artisanpack-ui/security-advanced-auth
```

## Run migrations

```bash
php artisan migrate
```

Creates 7 tables: `social_identities`, `sso_configurations`, `sso_identities`, `webauthn_credentials`, `user_devices`, `device_fingerprints`, `suspicious_activities`.

> Most migrations reference `users(id)`. Run Laravel's default migrations first.

## (Optional) Publish the config

```bash
php artisan vendor:publish --tag=security-advanced-auth-config
```

## (Optional) Publish the Livewire views

```bash
php artisan vendor:publish --tag=security-advanced-auth-views
```

Customize the published views at `resources/views/vendor/security-advanced-auth/livewire/*.blade.php`.

## Disable the bundled routes

If you want to wire your own controllers:

```php
'routes' => ['enabled' => false],
```

The 12 callback endpoints stop registering. You then need to wire `redirect`, `callback`, `unlink`, etc. yourself by calling the managers directly.

## Deeper topics

- [Requirements](installation/requirements.md)
- [Configuration](installation/configuration.md)
