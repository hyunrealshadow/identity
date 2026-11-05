# Security

[Back to README](../README.md) · [Login and Passkeys](../apps/login/README.md#passkeys) ·
[Deployment](../deploy/README.md)

Identity provides password protection, multi-factor authentication, session
management, and security auditing.

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

Sensitive credential changes require recent authentication. See the
[Login guide](../apps/login/README.md#passkeys) for enrollment and recovery setup.

## Session protection

Users can review their sessions and sign out individual devices or all other
sessions. Changing a password revokes other sessions and their access.

## API authorization

Each API resource owns its scope definitions. A scope is the canonical atomic
permission referenced by both client assignments and role permissions. Codes
are unique within a resource, and equal codes at different resources do not
grant access to each other. Protocol scopes have no API-resource owner and
cannot be added to a role as business permissions.

Users obtain effective permissions through direct roles and user groups.
Owner, Admin and Viewer are protected group/role presets, not a separate
administrator-binding system. Custom roles may reference built-in management
permissions; API admission uses permissions rather than role or group names.
Built-in definitions are immutable. Intrinsic account and session self-service
remains available to ordinary authenticated users.

A delegated user's scope is limited by the request, the client's exact scope
assignments, the enabled target resource and the user's current effective
permissions. Client-credentials tokens represent the client itself and may use
only the assignments marked `client_granted`; an unmarked assignment bounds
user-delegated requests and never becomes the client's own authority. They
require no human RBAC/MFA identity, separate management grant or
management-policy switch. Human-only management scopes cannot be granted to a
client and still reject machine principals. Granting a scope to the client
itself must fit the actor's delegation ceiling like a new assignment. Replacing
a client's scopes replaces the complete set, API and protocol scopes alike;
protocol scopes such as `openid` confer no permission, need no delegation
ceiling and are never granted to the client itself. A replacement withdraws
previously issued client artifacts and uses the client's UUID `version` as its
optimistic lock. A new interactive client starts with `openid`, `profile` and
`email`, plus `offline_access` when it may use refresh tokens; a machine client
starts with none.

Client management writes re-check management authority in their transaction,
lock the client, compare its `version` and audit the change. Built-in clients
cannot be edited, disabled or deleted. A protocol-settings change that alters
what the client may obtain, a credential revocation or rotation, and disabling
the client permanently withdraw its issued artifacts; display-text edits and
issuing an additional secret do not. A disabled client is rejected by every
protocol endpoint, including dynamic registration management and CORS, and
enabling it again never restores withdrawn artifacts. Deleting a client removes
its configuration, credentials, scope assignments, consents and artifacts.
Secret values are returned once when issued and are never readable afterwards.

Editing roles, groups or scope definitions does not imply permission to grant
arbitrary authority. An addition must fit the actor's pre-change effective
permissions or use explicit `management.permission.delegate`. That capability
must exist in both the token scope and live user authority; delegation beyond
one's own permissions requires recent AAL2 authentication. Authentication errors
from Guards and transactional checks expose the same MFA challenge.

Re-enabling an API resource can restore every enabled scope it owns. The same
delegation ceiling therefore applies to resource activation, using exact scope
identities within that resource. Resource write permission alone cannot restore
authority outside the actor's grantable set.

Authorization recovery is protected by capability, not preset names: at least
one enabled user with usable login credentials must retain the complete
management permission set. Authorization graph writes serialize this check
with their changes, so concurrent withdrawals cannot remove both remaining
recovery paths.

Custom API user authorization uses code flow with S256 PKCE and one target
resource. Authorization and refresh credentials retain semantic authorization
snapshots. Scope/client withdrawal, role or group authorization changes, and
resource disablement invalidate affected credentials during online checks;
restoring a relationship cannot revive an old credential. Metadata edits and
record UUID CAS versions do not change authorization fingerprints. External APIs
that validate JWTs offline must account for token lifetime or use introspection
for current authorization state.

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
or sent. Login and Console deny framing, and the API retains its existing page
framing restrictions. The standard OIDC session-monitoring endpoint keeps its
pre-existing protocol policy.

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
