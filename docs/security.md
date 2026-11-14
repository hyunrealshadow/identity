# Security

[Documentation index](README.md) · [Authorization model](authorization.md) ·
[Authentication flows](authentication-flows.md) ·
[Login and Passkeys](../apps/login/README.md#passkeys) ·
[Deployment](../deploy/README.md)

Identity provides password protection, multi-factor authentication, session
management, and security auditing. This page describes the controls an operator
or reviewer needs to know about; the full permission model, including effective
permissions, delegation, and credential authority, lives in the
[authorization model](authorization.md).

- [Password policy](#password-policy)
- [Multi-factor authentication](#multi-factor-authentication)
- [Session protection](#session-protection)
- [API authorization](#api-authorization)
- [Security auditing](#security-auditing)
- [Authentication browser windows](#authentication-browser-windows)

## Password policy

New passwords, including the initial administrator's password, must contain
12–1024 characters. Weak passwords, passwords resembling account identifiers,
and, when the breach check is enabled, known breached passwords are rejected.
Passwords are stored as salted hashes.

The typed setting `auth.password.breached_check_enabled` defaults to `true`.
When enabled, installation, user creation, and password changes require access
to the breached-password check service; an unavailable check blocks the
operation. Explicitly setting it to `false` skips only that external check;
local password validation and hashing still apply. See the
[deployment guide](../deploy/README.md#password-security-checks) for configuration.

## Multi-factor authentication

Accounts support TOTP authenticator apps, Passkey/WebAuthn, and single-use recovery
codes. Users can choose their preferred MFA method. A user-verified Passkey can
complete MFA without an additional password or OTP step.

MFA is an authentication-stage invariant: once a flow enters the MFA stage,
presenting the password again does not satisfy it. Assurance (`AAL2`) and
freshness (recent authentication) are separate requirements, and the windows are
measured from the moment the stage completed. Sensitive credential changes
require recent authentication; the exact windows per operation are listed with
the [authentication requirements](authorization.md#authentication-requirements).
See the [Login guide](../apps/login/README.md#passkeys) for enrollment and
recovery setup.

## Session protection

Users can review their sessions and sign out individual devices or all other
sessions. Changing a password revokes other sessions, so they can no longer
refresh or finish a pending flow. Sessions are bound to the sign-in they came
from, so signing out does not leave a half-authenticated flow behind.

Interactive tokens carry a `sid` claim naming their session. Revoking the
session makes pending code exchanges fail and stops the session's refresh
tokens from refreshing. Access tokens already issued stay valid until they
expire; use the token revocation endpoint when a specific access or refresh
token must be withdrawn. Machine tokens have no session and are withdrawn
through the client credential that issued them.

## API authorization

Every API call must satisfy the same conjunction: a token for the target
resource, an exact client scope assignment, the client's own token scopes, the
user's live effective permissions (or the client's own grants for machine
tokens), and the operation's authentication requirement. Consent approves a
request; it never widens that set. The [authorization model](authorization.md)
documents each step.

The parts most relevant to a security review:

- **Scopes belong to a resource.** Codes are unique within one resource, and the
  same code at another resource grants nothing there. Protocol scopes have no
  API-resource owner and cannot be attached to a role as a business permission.
- **Nothing is authorized by name.** Built-in groups and roles are ordinary RBAC
  definitions identified by a persisted `built_in` marker; no code path checks
  for a preset by display name or key. Intrinsic account and session
  self-service stays available to ordinary authenticated users.
- **Delegation is capped.** Adding permissions, assigning roles, and replacing a
  client's scopes must fit the actor's pre-change effective permissions, or use
  explicit `management.permission.delegate` with recent AAL2. Enabling a
  previously disabled resource re-checks its exact scopes against the same
  ceiling, so resource write permission alone cannot restore authority the actor
  cannot grant.
- **Recovery is protected.** Every authorization-graph write re-checks, before
  commit, that at least one enabled user with usable credentials still holds the
  complete management permission set. The check is serialized, so concurrent
  withdrawals cannot remove the last recoverable administrator.
- **Withdrawal is permanent.** Scope or client withdrawal, role and group
  changes, and resource disablement invalidate the credentials issued under the
  old grant during online checks. Re-enabling the object or re-granting access
  does not revive them. Display edits, metadata edits, and optimistic-lock
  version changes do not invalidate anything.
- **Offline validation has a known gap.** An external API that verifies JWTs
  without introspection sees the claims frozen at issuance, so it must either
  accept that window or introspect for current state.

Client management writes re-check management authority inside their transaction,
lock the client, compare its UUID `version`, and audit the change. Built-in
clients cannot be edited, disabled, or deleted. Secret values are returned once
when issued and are never readable afterwards.

## Security auditing

Identity records security-relevant changes to accounts, credentials, sessions,
and authorizations. Audit records exclude passwords, authentication secrets,
and token contents.

Repositories append audit facts explicitly in the same transaction as each
security transition. A failed audit insert rolls back the change. Request and
trace identifiers link the response to the fact; an anonymous login transition
keeps its actor unknown instead of impersonating the target account. Activity
touches, polling timestamps and replay counters do not produce change events.

The audit repository exposes append and read operations only. Database roles
must separately restrict direct modification of historical facts; application
append-only behavior does not restrict a privileged database operator.

## Authentication browser windows

Installation records issuer, login and console addresses independently. Those
settings configure first-party client callbacks and allowed API origins.
Authentication uses a browser popup; no first-party iframe allowlist is loaded
or sent. Login and Console deny framing. The API sends `X-Frame-Options: DENY`
on every path except `/openid/check_session`, which keeps its deliberate
framing exception for OIDC session monitoring.

The login transport and sealed account cookies retain SameSite=Lax. Popup
callbacks validate request state and target the exact opener origin. Console
also verifies the popup window, PKCE, ID-token signature and original subject
before replacing its in-memory session. Account callbacks exchange tokens on
the server and post only a state-bound result. Neither tokens nor PKCE verifiers
are sent through window messages. Closing or failing authentication never
replays a pending mutation. Popup blockers have an explicit retry and full-page
fallback.

An interrupted scope-state confirmation retains its original target, action and
UUID expected version in subject-and-issuer-scoped draft storage. Successful
reauthentication restores that confirmation without submitting it. The user
must explicitly retry; concurrent changes still produce the normal version
conflict rather than silently replacing the expected version.
