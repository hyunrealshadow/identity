# Security

[Back to README](../README.md) · [Login and Passkeys](../apps/login/README.md#passkeys) ·
[Deployment](../deploy/README.md)

Identity provides password protection, multi-factor authentication, session
management, and security auditing.

## Password policy

New passwords, including the initial administrator's password, must contain
12–1024 characters. Weak passwords, passwords resembling account identifiers,
and known breached passwords are rejected. Passwords are stored as salted hashes.

Installation and password changes require access to the breached-password check
service. If it is unavailable, the operation cannot complete. See the
[deployment guide](../deploy/README.md#password-security-checks) for configuration.

## Multi-factor authentication

Accounts support TOTP authenticator apps, Passkey/WebAuthn, and single-use recovery
codes. Users can choose their preferred MFA method. A user-verified Passkey can
complete MFA without an additional password or OTP step.

Sensitive credential changes require recent authentication. See the
[Login guide](../apps/login/README.md#passkeys) for enrollment and recovery setup.

## Session protection

Users can review their sessions and sign out individual devices or all other
sessions. Changing a password revokes other sessions and their access.

## Security auditing

Identity records security-relevant changes to accounts, credentials, sessions,
and authorizations. Audit records exclude passwords, authentication secrets,
and token contents.
