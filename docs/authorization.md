# Authorization model

[Back to the documentation index](README.md) · [Protocol reference](protocol.md) ·
[GraphQL API](graphql.md) · [Security](security.md)

Identity answers one question everywhere: **may this principal perform this
action on this target, right now?** The answer is computed from live relations,
never from a display name, a preset role name, a version counter, or a token
claim alone. This page describes that model; endpoint details live in the
[protocol reference](protocol.md), field-level requirements in the
[GraphQL API](graphql.md), and security properties in [security](security.md).

- [Principals](#principals)
- [Resources and scopes](#resources-and-scopes)
- [Permissions, roles, and groups](#permissions-roles-and-groups)
- [Effective permissions](#effective-permissions)
- [Client authority](#client-authority)
- [Authentication requirements](#authentication-requirements)
- [Delegation ceiling](#delegation-ceiling)
- [Recovery of instance authorization](#recovery-of-instance-authorization)
- [Credential authority](#credential-authority)
- [Built-in definitions](#built-in-definitions)
- [Enforcement layers](#enforcement-layers)
- [Audit](#audit)

## Principals

Two principal kinds present access tokens to the GraphQL API:

| Principal | Token source | Identity | May hold human requirements |
| --- | --- | --- | --- |
| User | interactive OAuth/OIDC flow | the user | yes |
| Client | client-credentials grant | the client itself | no |

A user is one identity for ordinary access and instance administration. There is
no administrator account type, no administrator binding, and no privileged role
name: administrative capability is exactly the effective permissions described
below. A machine principal never acquires a human identity, so any operation
declared `userOnly` rejects it, and the human authentication requirements
(session assurance, freshness, MFA) do not apply to machine operations that are
allowed at all.

Admission for any operation is the conjunction of:

1. a validated access token minted for this service (`aud` contains
   `urn:identity:graphql`),
2. the client's exact scope assignments covering the required scopes,
3. the token's granted scopes,
4. the user's live effective permissions, when a user is involved,
5. the applicable authentication requirement,
6. target-dependent checks — ownership, delegation, account state — performed
   inside the transaction.

Consent is not authority. A grant recorded during an interactive flow can only
select scopes the user already holds through roles and groups; it cannot create
permission.

## Resources and scopes

An **API resource** is a target API identified by a URI. A **scope** belongs to
exactly one resource (`scope.resource_id`) and is the canonical atomic
permission: `client_scope` and `role_permission` reference the same scope rows,
so there is no second permission catalog to drift.

- A scope `code` is unique **within its resource**. The same code at another
  resource is a different permission; equal codes never merge or transfer
  authority.
- The built-in GraphQL resource is `urn:identity:graphql`.
- `openid`, `profile`, `email`, `address`, `phone`, and `offline_access` are
  global protocol scopes. They have no resource owner, cannot be added to a role
  as business permissions, and confer no instance authority.
- Request selectors such as `account.*`, `session.*`, or `management.*` expand
  only against registered scopes at the requested resource. A selector may be
  used at any hierarchy level, selects descendants rather than the prefix
  itself, and never creates a permission. Persistent assignments store concrete
  scope IDs, never wildcard definitions.
- Resource ownership and code are fixed after creation. Re-enabling a resource
  restores its enabled scopes, which is an authorization change and is checked
  against the actor's delegation ceiling.

Display text (`name`/`names`, `description`/`descriptions`) is locale data. It
never participates in a decision.

## Permissions, roles, and groups

A **permission** is identified by `(resource, code)`. A **role** is an explicit
set of permissions. A **group** collects users and receives permissions through
roles. Users receive roles directly or through group membership.

The model deliberately has no implicit inheritance:

- no wildcard permissions,
- no implicit write ⇒ read implication,
- no deny rules or precedence,
- no role hierarchy,
- no containment inferred from similar names or shared prefixes,
- no "future permissions" absorbed by a role.

Instead, every effective permission keeps its provenance so interfaces can
explain *why* access exists: a direct user-role binding, or a group path
(membership → group → group role → role). A group source is never rewritten as
a direct binding, and removing one source does not remove another still-valid
source.

Roles, groups, and permissions carry localized default text plus translations.
Objects are linked by identity, not by name; renaming never re-authorizes.

## Effective permissions

For a human principal, effective permissions are the union of:

- active direct user-role bindings,
- role permissions reachable through enabled group memberships, enabled group
  roles, enabled roles, and enabled permissions on the matching resource.

For a machine principal, the applicable catalog is the client's own granted
scopes — there is no user, no group path, and no MFA.

The projection returns each permission with its sources and group sources. This
is what `effectivePermissions` exposes and what the Console and account center
display. The projection is a *view*: admission re-checks live relations, so a
stale projection cannot grant anything.

Revocation is permanent for the withdrawn relation. Revoking a binding and
granting it again creates a new relation; re-enabling an object or re-granting
access does not revive credentials that were withdrawn before.

## Client authority

Clients have two distinct ceilings:

| Assignment | Meaning |
| --- | --- |
| `client_scope` | what the client may request on behalf of a user |
| `client_granted` | what the client itself may use (client-credentials) |

An assignment that bounds user-delegated requests is not the client's own
authority. A client-credentials token may use only `client_granted` scopes, and
human-only management scopes cannot be granted to a client at all — a machine
principal is still rejected for them.

Additional rules:

- Public dynamic registration may request protocol and intrinsic account
  self-service scopes; it cannot declare arbitrary API permissions.
- Replacing a client's scopes replaces the complete set, API and protocol scopes
  alike; when the authorization boundary actually changes, previously issued
  client artifacts are withdrawn. The client's UUID `version` is the optimistic
  lock. Protocol scopes need no delegation ceiling and are never granted to the
  client itself.
- A new interactive client starts with `openid`, `profile`, `email`, plus
  `offline_access` when it may refresh. A machine client starts with none.
- Granting a scope to the client itself must fit the actor's delegation ceiling,
  exactly like a new role assignment.

## Authentication requirements

Authentication assurance and freshness are separate requirements, and both are
part of an operation's published policy.

| Requirement | Meaning |
| --- | --- |
| `SESSION` | any valid interactive session |
| `AAL2` | a second factor has been verified in this session |
| `RECENT` | session authenticated within the recent window (300 s) |
| `RECENT_AAL2` | AAL2 verified within the recent window (300 s) |
| `ACCOUNT_SECURITY` | security operation whose requirement depends on the account's registered factors |

`maxAge` is the maximum age of authentication in seconds. `elevatedMaxAge` is
the window once the account has registered a second factor; it is 3600 s (one
hour) for account-security operations, while the ordinary recent window is
300 s.

Once a flow has entered MFA, a password is not an alternative: MFA is an
authentication-stage invariant, not a fallback. When current authentication does
not satisfy the actual requirement, the client starts reauthentication with a
browser popup (never an embedded iframe), validates callback origin, state,
window, and subject, and **does not replay** the pending write. The user submits
again explicitly.

A client-credentials token satisfies no human requirement. Management scopes
marked machine-allowed do not apply human assurance to machine operations; the
rest are rejected for machine principals by policy.

## Delegation ceiling

Editing roles, groups, or scope definitions does not confer the right to grant
arbitrary authority. An addition must fit the actor's **pre-change** effective
permission set, captured before the mutation.

Writing outside that set is refused with a delegation error unless all of the
following hold:

1. the presented token carries `management.permission.delegate`,
2. the actor's *live* authority also contains it,
3. the actor authenticated with recent AAL2 (300 s window).

A machine principal has an empty ceiling. The same rule governs re-enabling a
resource, using exact scope identities inside that resource: resource write
permission alone cannot restore authority outside the actor's grantable set.

## Recovery of instance authorization

An instance must never lose every path back into its own authorization graph.
After each authorization-changing mutation, and before the audit fact is
appended and the transaction commits, Identity proves a **recoverable
authorization administrator** still exists. The check runs while holding the
lifecycle lock, so concurrent withdrawals cannot each remove one of the last two
paths.

A candidate must satisfy all of:

- the user is enabled,
- the user is not permanently locked (an automatic, time-bounded lock still
  counts),
- the user has a password or passkey credential that has not expired,
- the user holds the complete built-in management permission set on
  `urn:identity:graphql`, evaluated through live authority.

If no candidate remains, the mutation fails with a "no recoverable authorization
administrator remains" error and the transaction rolls back. Recovery is by
capability, not by membership in a named preset: a custom role carrying the
complete management permission set protects the instance just as the Owner
preset does.

## Credential authority

Credentials issued for an API request or a token record retain the semantic
authorization facts they were issued under:

- the resource identity and its authorization policy version,
- the user identity and the user's authorization version, plus the bindings and
  roles that were in force.

When such a credential is used, Identity re-validates those facts. Withdrawal of
a scope assignment, a revoked role or group relation, resource disablement, or a
changed policy version invalidates affected credentials during the online check.
Restoring the relationship does not revive the old credential; a new grant
creates a new relation with a new identity.

The following do **not** invalidate authority by themselves:

- display-name, description, or translation edits,
- record `version` changes used for optimistic locking,
- re-enabling an object whose grant was never revoked.

`version` is a UUID equality token, not a counter and not proof of authority:
compare the submitted value, replace it on success, and never use equality as an
authorization argument. A resource's policy version is a semantic fingerprint of
its authorization meaning, not a modification count.

Clients that validate JWTs offline cannot see these checks; they must rely on
short token lifetimes or call introspection for current state.

## Built-in definitions

Three presets ship with the schema. Each is an ordinary protected role plus a
protected group carrying explicit permissions:

| Preset | Permissions | Notes |
| --- | --- | --- |
| Owner | all 44 management scopes | installation adds the first user to this group |
| Admin | 39 | day-to-day administration; no settings write, no key create/rotate/revoke, no permission delegation |
| Viewer | 16 | read-only management views |

Protection is decided by the persisted `built_in` flag, never by a fixed
identifier or a name, so a user-created object that happens to share a display
name stays editable. Built-in definitions are immutable; membership in the
built-in groups is managed separately and remains adjustable by authorized
actors.

Seed identities are deterministic: UUIDv8 values derived from SHA-256 over
`identity/rbac/role/{owner|admin|viewer}`, `identity/rbac/group/...`, and
`identity/rbac/permission/<scope name>`. The seed uses those identities only to
stay idempotent; runtime authorization reads effective permissions and the
`built_in` flag. Re-running the seed maintains definitions without restoring
revoked grants.

Custom roles may reference built-in permissions, and an instance administrator
is simply a user holding the relevant permissions — losing them removes the
capability, not the account or its unrelated grants.

## Enforcement layers

Declarations and enforcement come from the same policy definitions:

1. **Published requirement.** Every root field and every additionally protected
   nested field carries a repeatable `@access` directive generated from the same
   `ManagementScope`/`ApiScope` definition used by the guard. Repeated
   declarations are conjunctive. `runtime: true` marks requirements that a
   client cannot prove from its token — target, ownership, live authorization,
   delegation, or account state.
2. **Transport admission.** The GraphQL entry point validates the bearer token,
   its audience, and the account's enabled/unlocked state before the document
   runs.
3. **Application and transaction checks.** Guards, application services, and
   transactional repositories re-check live authority, optimistic lock, target
   ownership, delegation ceiling, and recovery. These checks are authoritative.

Frontend preflight (`@identity/graphql-access`) evaluates the same directives to
improve interaction: it traverses nested selections, aliases, fragments,
conditions, and variable defaults, refuses locally when a scope is missing, and
starts reauthentication when assurance is insufficient. It never issues
authority, expands scopes, fabricates identifiers, or replays a write, and
server-side checks remain in place for deployment skew and state changes.

## Audit

Security-relevant changes write a semantic audit fact **in the same transaction**
as the business change. A failed audit insert rolls back the change, so an
accepted response implies a persisted fact. Facts carry their own stable `oid`,
the actual actor (an anonymous login keeps its actor unknown rather than
impersonating the target), the action, the target, and request/trace correlation.

The repository exposes append and read operations only; restricting direct
modification of history is a database-role responsibility. A reason is optional
everywhere — creating, editing, enabling/disabling, unlocking, deleting,
granting, and revoking — and never becomes an approval workflow. Activity
touches, polling timestamps, and replay counters do not produce change events.

Migrations carry structure and necessary historical backfills only. There are no
authorization or audit business triggers: the seed entry point initializes
trusted definitions, and repository transactions perform version changes,
revocation, protection checks, and audit inserts explicitly.
