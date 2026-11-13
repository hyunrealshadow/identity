# GraphQL contracts

`schema.graphql` is exported from the executable schema. `error-catalog.json`
and `management-scopes.json` are exported from typed backend catalogs; regenerate
them with the root `graphql:schema`, `errors:catalog`, and `scopes:catalog`
commands. Their corresponding `*:check` commands detect stale exports.

The single `/graphql` endpoint uses flat functional queries and explicitly named
mutations. OAuth/OIDC and login interaction endpoints retain their protocol form.

Schema introspection is enabled on that endpoint and needs the same validated
access token as any other operation; a request without one is rejected before
the document runs. The `graphql.max_depth` default admits the canonical
introspection document, which nests 13 levels deep. A document rejected by the
`graphql.max_depth` or `graphql.max_complexity` limits reports `28110` or `28111`
with the configured limit instead of the generic invalid-request `28100`.

User, group, role, and scope connections expose `totalCount`, including their
filtered nested views and client scope assignments. The count covers the full
authorized filter rather than the cursor-bounded page. It is calculated only
when selected, through the same predicates as the row query; no persisted count
or optimistic-lock version is involved. Counts inherit the parent operation's
authorization requirements. Cursor pagination still determines which pages can
be addressed; a total count does not provide a cursor for an unvisited page.

The static management Console requests only `openid profile email`, `account.read`
and exact management scopes. Its bootstrap queries `effectivePermissions` and
`instanceInfo`; validated ID-token claims supply the operator summary, and
`account { theme }` applies the operator's theme preference. Personal profile, sessions
and credential management remain in Login's account center, linked by the public
`accountUrl` configuration without passing Console tokens. Self-service fields
below remain available to Login and authorized consumers.

The account center stores the preferred IANA time zone through
`updateProfile(input: { zoneInfo: ... })` and reads `account.zoneInfo`.
Omitting the field preserves it; null or an empty value clears it so interfaces
follow the browser. Invalid identifiers return a localized `zoneInfo` field error.
The standard `profile` claim `zoneinfo` supplies Console's time-zone preference
after authentication; no extra scope or UserInfo call is required. Time-zone
changes affect presentation and calendar boundaries, not elapsed durations or
date-only values such as birthdays.

## Current authorization map

Every request requires a validated access token. User-only fields additionally
use async-graphql's native `Guard`; machine principals cannot call them.

| Functional fields | Scope | Subject and authentication |
| --- | --- | --- |
| `account`, `security`, `passkeys` | `account.read` | Current user |
| `sessions` | `session.read` | Current user's sessions |
| `node`, `nodes` | Determined by decoded type | User: `account.read` plus current-user target; session: `session.read` plus owned-session lookup |
| `effectivePermissions`, `instanceInfo` | No additional scope | Current validated principal; management discovery never grants authority |
| `instanceOverview.users` | `management.user.read` | Live management authority and catalog authentication policy |
| `instanceOverview.applications` | `management.client.read` | Live management authority and catalog authentication policy |
| `instanceOverview.sessions` | `management.session.read` | Live management authority and catalog authentication policy |
| `instanceOverview.resources` | `management.resource.read` | Live management authority and catalog authentication policy |
| `updateProfile`, `updatePreferredMfaMethod` | `account.update` | Current user |
| `updateUsername`, `updateEmail` | `account.update` | Current user, recent authentication |
| `revokeSession`, `revokeOtherSessions` | `session.revoke` | Current user's sessions |
| `prepareMfaManagement`, `prepareMfaRecoveryCodes`, `beginPasskeyRegistration`, `finishPasskeyRegistration`, `deletePasskey`, `beginTotpEnrollment`, `confirmTotpEnrollment`, `changeTotpEnrollmentAlgorithm` | `account.update` | Current user; recent authentication, elevated to AAL2 when an MFA factor exists |
| `changePassword` | `password.change` | Current user; same MFA-aware authentication requirement |
| `disableTotp`, `regenerateRecoveryCodes` | `account.update` | Current user, elevated AAL2 authentication |

Existing account scope hierarchy is retained. Client assignment still requires
explicit names. Management scopes have no prefix wildcard or implicit write/read
inheritance. The exact 36-entry catalog defines viewer/admin/owner and machine
ceilings. A binding/grant, live versions, client assignment, resource coverage,
token scope and authentication policy must all agree.

Management CRUD fields and business RBAC issuance are delivered in later modules.
The foundation does not expose placeholder management mutations. New RBAC
resources fail closed until their role projection is implemented.

The instance dashboard reads actual aggregates rather than displaying scope and
authentication diagnostics. Each nullable aggregate is guarded before its own
query runs, so missing permission or a failed aggregate does not become zero or
discard another permitted result. Registrations cover exactly seven calendar
dates in `instanceOverview.users(timeZone: ...)` through `generatedAt`; the
parameter defaults to UTC and Console supplies the user's effective time zone.
Daily boundaries account for daylight-saving transitions. Valid sessions exclude revoked/expired sessions and
unavailable accounts, and do not mean devices currently online. Aggregate reads
produce query spans, not security-change audit facts.

User/session nodes and mutation payloads currently come only from the authorized
self-service lookup or transition. Any future management return path must define
its target/field policy before reusing these types.

## Persistence

Migrations contain structure and necessary historical backfills. The existing
seed entry initializes trusted definitions. Rust repository transactions explicitly
perform version changes, revocation, owner protection and semantic audit inserts.
There are no authorization or audit business triggers. Audit failure rolls back
the transition; request and optional trace IDs correlate the fact with responses.
