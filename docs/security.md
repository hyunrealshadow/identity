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

Two authentication settings, both off by default:

- `auth.password.max_age_days` (Console: *Password lifetime*, 0–3650, `0`
  off): a password set longer ago than this must be replaced at the next
  sign-in, after its factors are verified. Sessions already open are not cut
  short.
- `auth.password.history_count` (Console: *Passwords not reused*, 0–24, `0`
  off): a new password may not repeat this many recent passwords, the current
  one included. A replaced hash is kept as an expired `user_credential` row of
  type `password`, which every credential read ignores; only as many as the
  setting needs are kept, and lowering it drops the rest at the next change.

### Administrator credential actions

Each of these re-checks `management.user.write` for the target inside its
transaction, compares the user `version`, writes its audit record in the same
transaction, and ends every session of the user with its grants. An
administrator cannot reset their own password, clear their own second factors,
or require a password change on their own account through user management;
self-service sign-in methods belong in the account center.

- **Invite** (`createUser` with `sendInvitation`, or `sendUserInvitation`,
  audit `USER_INVITE`) emails a seven-day link with which a user who has no
  password yet sets their own; see
  [Invitations](authentication-flows.md#invitations). It does not end sessions,
  since such a user has none.
- **Reset password** (`resetUserPassword`, audit `USER_PASSWORD_RESET`) stores a
  generated temporary password (16 characters mixing uppercase, lowercase,
  digits, and symbols without look-alikes), returns it once, requires a change
  at the next sign-in, and ends a lockout from failed attempts. An account
  without a password receives one.
- **Require a password change** (`updateUser` with `requiredActions`) adds or
  removes `CHANGE_PASSWORD` without changing the password. `requiredActions`
  is the user's set of actions the next sign-in must complete, stored as one
  JSON array on the user so later policies add an action rather than a column;
  the list replaces the set, and an omitted list keeps it. Any password change
  by the user removes `CHANGE_PASSWORD`. Expiry from `max_age_days` is
  evaluated at sign-in and never stored there.
- **Clear second factors** (`resetUserMfa`, audit `USER_MFA_RESET`) removes the
  authenticator app, recovery codes and passkeys. It is refused while the user
  has no password, so it cannot leave an account without a way to sign in.
- **Revoke sessions** (`revokeUserSessions`, audit `USER_SESSION_REVOKE`) ends
  the listed sessions, or all of them, with the codes and tokens issued from
  them. `User.sessions` lists the active ones for `management.user.read`.
- **Delete** (`deleteUser`, audit `USER_DELETE`) applies only to a disabled
  user. Credentials, sessions, consents, group memberships and role
  assignments go with it; roles or memberships it granted to others stay with
  no granter recorded. The audit log keeps the history, and the recovery
  protection below still applies.

### Self-registration

Self-registration (`auth.login.registration_enabled`) is off by default. When
it is on, the address is verified before the account exists and the
registration page answers the same for every address; see
[Self-registration](authentication-flows.md#self-registration). A username
that is already taken is reported when the account is created.

### Account enumeration

The setting `auth.login.identifier_enumeration_allowed` controls whether sign-in
may reveal that an entered email or username has no account. Turning it off
sends every identifier to the password step and reports a single
account-or-password error; see
[concealing whether an account exists](authentication-flows.md#concealing-whether-an-account-exists).

### Email delivery

Email is sent through the SMTP server in the `email.delivery` settings
(Console: *Instance › Email*), with STARTTLS, implicit TLS, or no transport
security, and either a username and password or OAuth 2.0 `XOAUTH2`. For
XOAUTH2 the instance obtains access tokens from the configured token endpoint
with a refresh token or client credentials and caches them until shortly before
they expire. The SMTP password, OAuth client secret and refresh token are
stored data-protected, are never returned by the API, and appear in the audit
log only as a fingerprint; leaving one empty when saving keeps the stored
value. An operator can send a test message with the saved settings.

Each message kind has one email template (`email.templates`): default content
and optional translations keyed by language tag, each a subject and an HTML
body. A kind uses its built-in template until an operator replaces it. Templates
use Tera syntax; each is rendered with a fresh engine that holds only that
template and no custom functions, values are escaped in the HTML body, and a
template is rendered with sample values before it is saved. The plain-text
alternative of a message is derived from its rendered HTML when it is sent.
The Console shows the rendered draft in a sandboxed frame that cannot run
scripts. Audit records keep each language's subject and a digest of its body.

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

Identity keeps one append-only `audit` journal with four categories:

| Category | Covers |
|---|---|
| `management` | Users, clients, roles, groups, scopes, API resources, keys, and instance settings |
| `account` | A person's own profile, identifiers, password, authenticator app, recovery codes, and passkeys |
| `sign_in` | Sign-in results, sign-ins to a client with an existing session, rejected client credentials, account lockout, reauthentication, and ended sessions |
| `authorization` | Consent, device approvals, authorization revocation, and token revocation or replay |

Each record names a public action (such as `role_update` or `sign_in`), its
outcome (`success` or `failure` with a failure reason), the actor (`user`,
`client`, `system`, or `anonymous`), the target, the OAuth client involved, and
the request's client IP address, User-Agent, and request/trace identifiers.
Actor and target names are snapshotted when the record is written, so the log
stays readable after renames and deletions. Changes list only the attributes
that changed: values for ordinary fields, added and removed members for
collections such as roles, permissions, and scopes, and a bare "changed" marker
for secrets. Passwords, authenticator secrets, recovery codes, and token
contents are never recorded. Enumerated columns hold the stable values of the
backend enums; a stored value the backend does not recognize is rejected as a
corrupt record.

A sign-in produces one record, not one per protocol step: success with the
methods used, or failure with its reason. A failure before the person is
authenticated has an anonymous actor and the account as its target. Rejections
at identifier entry are recorded too: `account_locked` and `account_disabled`
target the account, while `unknown_account` has no target and never stores the
entered identifier; its IP address and User-Agent still show where repeated
attempts come from. Login state
transitions, activity touches, polling timestamps, and replay counters do not
produce records.

A client secret or assertion rejected at any client-authenticated endpoint
(token, PAR, revocation, introspection, device authorization) is a failed
`client_authenticate` record with an anonymous actor and the client as its
target; an unknown `client_id` or a malformed request is not. Ending a session
through RP-initiated logout names the client when a verified `id_token_hint` or
an accepted registered post-logout redirect URI identifies it. Work Identity
does on its own, such as installation and scheduled key rotation, is recorded
with the `system` actor.

Repositories write each record in the same transaction as the change it
describes, in a single statement, so a failed audit insert rolls the change back
and auditing adds no extra round trip. The journal stores IP addresses and
User-Agents, which are personal data; plan retention accordingly.

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
