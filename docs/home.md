---
title: ArtisanPack UI Security Advanced Auth Documentation
---

# ArtisanPack UI Security Advanced Auth

Enterprise authentication for Laravel: WebAuthn / FIDO2, SSO (SAML / OIDC / LDAP), social login, biometric authentication, device fingerprinting, and auth-flow suspicious activity detection.

This package is part of the **ArtisanPack UI Security 2.0** split.

## What's in this package

- **WebAuthn / FIDO2** — passkey + security-key authentication
- **SSO** — SAML 2.0, OIDC, LDAP with bundled callback routes + controllers
- **Social authentication** — 8 OAuth providers (Apple, Facebook, GitHub, Google, LinkedIn, Microsoft, generic OIDC + OAuth2 abstracts)
- **Biometric** — pluggable provider model
- **Device fingerprinting + trusted devices**
- **Suspicious activity detection** for auth-flow patterns
- **5 Livewire components** + 12 callback routes ship out of the box

## Documentation map

- [Getting Started](getting-started.md) — 5-minute install + first social provider
- [Installation](installation.md)
- [Usage](usage.md) — per-subsystem reference
- [Advanced](advanced.md) — extending providers, custom flows
- [FAQ](faq.md)
- [Troubleshooting](troubleshooting.md)

## Related packages

| Package | Scope |
|---|---|
| [`artisanpack-ui/security`](https://github.com/ArtisanPack-UI/security) | Core: sanitization, escaping, CSP, security headers |
| [`artisanpack-ui/security-auth`](https://github.com/ArtisanPack-UI/security-auth) | 2FA, password complexity, account lockout |
| [`artisanpack-ui/rbac`](https://github.com/ArtisanPack-UI/rbac) | Roles, permissions, Gate integration |
| [`artisanpack-ui/secure-uploads`](https://github.com/ArtisanPack-UI/secure-uploads) | File validation, malware scanning |
| [`artisanpack-ui/security-analytics`](https://github.com/ArtisanPack-UI/security-analytics) | Event logging, anomaly detection, SIEM, dashboards |
