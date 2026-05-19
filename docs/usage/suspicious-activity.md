---
title: Suspicious Activity Detection
---

# Suspicious Activity Detection

`SuspiciousActivityService` (bound to `SuspiciousActivityDetectorInterface`) catches auth-flow patterns that suggest takeover attempts. Distinct from `artisanpack-ui/security-analytics` — this package is auth-specific (impossible travel during login, proxy / Tor detection at sign-in time, etc.).

## Shipped patterns

11 types defined on `SuspiciousActivity`:

| Constant | What it catches |
|---|---|
| `TYPE_BRUTE_FORCE` | Many failed login attempts on a single account |
| `TYPE_IMPOSSIBLE_TRAVEL` | Two logins from geographically distant IPs in too short a time |
| `TYPE_ANOMALOUS_LOGIN` | Login deviating from user's baseline (time, location, device) |
| `TYPE_PROXY_DETECTED` | Login from a known proxy IP |
| `TYPE_TOR_DETECTED` | Login from a Tor exit node |
| `TYPE_DATACENTER_IP` | Login from a datacenter IP range (suspicious for a regular user) |
| `TYPE_MULTIPLE_FAILURES` | Sustained failure rate above threshold |
| `TYPE_DEVICE_CHANGE` | Login from a never-before-seen device |
| `TYPE_UNUSUAL_TIME` | Login at a time outside user's typical window |
| `TYPE_SESSION_HIJACKING` | Session token used from a different IP / UA mid-session |
| `TYPE_CREDENTIAL_STUFFING` | Same password tried across many accounts from one source |

## Detecting

```php
use ArtisanPackUI\SecurityAdvancedAuth\Authentication\Contracts\SuspiciousActivityDetectorInterface;

$detector = app( SuspiciousActivityDetectorInterface::class );

// At login
$activity = $detector->analyzeLogin( $user, $request );

if ( $activity && $activity->severity === 'critical' ) {
    // Refuse login, lock account, etc.
}
```

The service writes a `SuspiciousActivity` row per detection. The bundled `SuspiciousActivityList` Livewire component renders them.

## Severity bands

- `SEVERITY_LOW` — gray. Worth tracking, not actionable on its own.
- `SEVERITY_MEDIUM` — yellow. Show the user, log to audit, maybe send notification.
- `SEVERITY_HIGH` — orange. Step-up auth required, alert security team.
- `SEVERITY_CRITICAL` — red. Auto-lock the account, force password reset, page on-call.

Configure auto-action thresholds:

```php
'suspicious_activity' => [
    'auto_lock_threshold' => 'high',   // auto-lock for severity >= this
],
```

## Recommended actions

`SuspiciousActivity` exposes `ACTION_*` constants for canonical response actions:

- `ACTION_NONE` — log only
- `ACTION_CAPTCHA` — challenge with CAPTCHA on next attempt
- `ACTION_STEP_UP` — require step-up auth
- `ACTION_BLOCK` — refuse the operation
- `ACTION_LOCKOUT` — lock the account

The service picks an action based on severity + type; the calling code can override.

## Integration with security-analytics

If `artisanpack-ui/security-analytics` is installed, its `SuspiciousActivityService` covers a broader scope (any activity, not just auth flows). This package's service writes to a separate `suspicious_activities` table — both packages can coexist; the analytics one is the broader audit surface, this one is the auth-specific path.

Migration table-name conflict between the two packages is tracked as a separate bug — for now, install only one, or skip the duplicate migration.
