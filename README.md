# ArtisanPack UI — Security Advanced Auth

Enterprise authentication for Laravel: WebAuthn / FIDO2 passwordless auth, SSO (SAML / OIDC / LDAP), social login, biometric authentication, and device fingerprinting.

This package is part of the **ArtisanPack UI Security 2.0** split — the enterprise-auth features previously bundled inside `artisanpack-ui/security` (1.x) live here in 2.0+.

> **Status:** scaffold. Content is being extracted from `artisanpack-ui/security` 1.x in a follow-up PR.

## Installation

```bash
composer require artisanpack-ui/security-advanced-auth
```

## Sibling packages

| Package | Scope |
|---|---|
| [`artisanpack-ui/security`](https://github.com/ArtisanPack-UI/security) | Core: input sanitization, output escaping, KSES, CSP, security headers |
| [`artisanpack-ui/security-auth`](https://github.com/ArtisanPack-UI/security-auth) | 2FA, password security, account lockout, session management |
| [`artisanpack-ui/rbac`](https://github.com/ArtisanPack-UI/rbac) | Roles, permissions, hierarchy, Blade directives, Gate integration |
| [`artisanpack-ui/secure-uploads`](https://github.com/ArtisanPack-UI/secure-uploads) | File validation, malware scanning, secure storage |
| [`artisanpack-ui/security-analytics`](https://github.com/ArtisanPack-UI/security-analytics) | Event logging, anomaly detection, SIEM, dashboards |
| [`artisanpack-ui/compliance`](https://github.com/ArtisanPack-UI/compliance) | GDPR / CCPA / LGPD compliance tools |
| [`artisanpack-ui/security-full`](https://github.com/ArtisanPack-UI/security-full) | Meta-package bundling all of the above |

## Contributing

As an open source project, this package is open to contributions from anyone. Please [read through the contributing guidelines](CONTRIBUTING.md) to learn more about how you can contribute to this project.
