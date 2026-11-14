# GraphQL API

[Back to the documentation index](README.md) · [Authorization model](authorization.md) ·
[Protocol reference](protocol.md)

`/graphql` is the single API for account self-service, security settings, and
instance management. It complements the OAuth/OIDC and login-interaction
endpoints; it does not duplicate them as a REST management API.

- [Transport](#transport)
- [Schema conventions](#schema-conventions)
- [Access requirements](#access-requirements)
- [Pagination](#pagination)
- [Account and dashboard fields](#account-and-dashboard-fields)
- [Limits](#limits)
- [Errors](#errors)
- [Management scope catalog](#management-scope-catalog)
- [Generated artifacts](#generated-artifacts)

## Transport

| Aspect | Behaviour |
| --- | --- |
| Method | `POST` with `Content-Type: application/json`; `GET` with `query`, `variables`, and `operationName` in the query string |
| Mutations | `POST` only; a `GET` mutation returns `405` with `Allow: POST` |
| Authentication | `Authorization: Bearer <access token>`; the token audience must include `urn:identity:graphql` |
| Origin | Requests carrying a `Origin` header must match `graphql.allowed_origins` (public/login/console addresses); otherwise `403` with `OriginDenied` |
| Response type | `application/graphql-response+json; charset=utf-8` |
| Binding | The public origin, or a dedicated `graphql.server` binding/port |
| GraphiQL | Served on `GET /graphql` without a `query` parameter in non-production environments only |
| CORS | Preflight allows `authorization`, `content-type`, and `accept-language` |

Before any document runs, Identity validates the bearer token, requires the
GraphQL audience, and rejects tokens whose user is now disabled or locked. A
missing or invalid token yields `401` with
`WWW-Authenticate: Bearer realm="graphql", error="invalid_token"`.

## Schema conventions

- Queries are **flat functional fields** (`user`, `users`, `role`, `client`,
  `instanceOverview`, `effectivePermissions`, …). There are no `viewer` or
  `management` wrapper namespaces.
- Mutations are **explicitly named verbs** (`createUser`, `setRolePermissions`,
  `rotateAndRevokeKey`, …). A mutation that modifies an existing managed object
  takes an optimistic-lock token named for that object
  (`expectedVersion`, `expectedUserVersion`, …) and returns the replacement
  version. Account self-service inputs and session/credential actions address
  the current session or a named identifier instead.
- Mutation inputs accept `clientMutationId: String` (Relay convention); management
  inputs additionally accept `reason: String! = ""`. A reason is optional
  everywhere and never gates the operation.
- Payloads are typed per action (`CreateUserPayload`, `DeleteClientPayload`, …)
  and return the affected identifier, the new `version` when relevant, and
  either the updated node or a deletion flag.
- Object identifiers on the wire are Global IDs: unpadded base64url of
  `<Type>:` plus the 16 UUID bytes. Raw UUIDs are rejected; see
  [Identifiers](protocol.md#identifiers).
- Collection fields follow the Relay connection shape with
  `edges { cursor node }`, `pageInfo`, and an additional `totalCount`.
- Localized definitions accept `name`/`description` defaults plus optional
  `names`/`descriptions` translation maps; the viewing client selects the
  language and fallback.

## Access requirements

Every root field — and every nested field that is protected — publishes a
repeatable `@access(policy: AccessPolicy!)` directive. Repeated declarations are
**conjunctive**: all of them must hold.

```graphql
createGroup(input: CreateGroupInput!): GroupPayload!
  @access(policy: {
    scopes: ["management.group.write"]
    authentication: RECENT_AAL2
    maxAge: 300
    elevatedMaxAge: null
    userOnly: true
    runtime: true
  })
```

| Argument | Meaning |
| --- | --- |
| `scopes` | exact scope codes required at the same time; never inferred from prefixes |
| `authentication` | `SESSION`, `AAL2`, `RECENT`, `RECENT_AAL2`, or `ACCOUNT_SECURITY` |
| `maxAge` | maximum age of authentication in seconds; `null` means no fixed freshness window |
| `elevatedMaxAge` | freshness window once the account has registered a second factor |
| `userOnly` | machine principals are rejected |
| `runtime` | the server must additionally prove target, ownership, live authorization, delegation, or account state — the client cannot preflight it |

The values come from the same definitions the server enforces: management
scopes from the catalog below, account and self-service windows from the
authentication policy. The [authorization model](authorization.md) explains
assurance, freshness, and delegation.

Both frontends consume the generated metadata through `@identity/graphql-access`
to preflight the operation they are about to send: they traverse nested
selections, aliases, fragments, conditions, and variable defaults, refuse
locally on a missing scope, and start the existing reauthentication flow when
assurance is insufficient. Preflight is advisory — ownership, live authority,
delegation, and transaction checks stay on the server, and a successful
authentication never replays the pending write automatically.

## Pagination

List fields use pointer pagination with a stable ordering and a unique
tie-breaker (the entity's Global ID or a composite cursor):

| Argument | Meaning |
| --- | --- |
| `first` + `after` | forward pagination from an exclusive cursor |
| `last` + `before` | backward pagination from an exclusive cursor |
| `orderBy` | supports the field's documented sort keys; the tie-breaker makes the order total |

`first` and `last` are validated to at least `1`, with a page cap of `100`
(most list fields declare `1..=100` directly). The session listing compares the
requested size with the configured `graphql.max_page_size` (default `100`) and
rejects anything larger with a field error naming the limit. `pageInfo` reports
accurate `hasNextPage`/`hasPreviousPage` in both directions. `totalCount` covers
the full authorized filter for the parent operation, not just the cursor-bounded
page; it is computed only when selected, and shares the parent's requirements. A
total count is not a cursor: it cannot address an unvisited page.

## Account and dashboard fields

Two field families carry behaviour that is easy to get wrong.

**Account preferences.** `updateProfile(input: { zoneInfo })` stores the preferred
IANA time zone and `account.zoneInfo` reads it back. Omitting the field preserves
the stored value; an explicit null or empty string clears it, so interfaces
follow the browser again. Invalid identifiers return a localized `zoneInfo` field
error. The value is exported as the standard `profile` claim `zoneinfo`, so a
client that requests `profile` receives it without an extra UserInfo call. Time
zone changes affect presentation and calendar boundaries, not elapsed durations
or date-only values such as birthdays.

**Dashboard aggregates.** `instanceOverview` returns real instance aggregates,
each loaded only after its own authorization check, so a missing permission or a
failed aggregate stays absent instead of becoming zero and does not discard
another permitted result. `users(timeZone:)` returns exactly seven ascending
local calendar dates ending with the local day that contains `generatedAt`; the
window starts at the first valid local instant six days earlier, so a
daylight-saving gap or an ambiguous midnight does not shift a bucket, and the
upper bound is exclusive to leave out rows created after the snapshot. Active
sessions exclude revoked, expired, and unavailable-account sessions, and do not
mean that a device is online. Aggregate reads produce query spans, not
security-change audit facts.

## Limits

| Setting | Default | Enforced by |
| --- | --- | --- |
| `graphql.max_depth` | `15` | admits the canonical 13-level introspection document; deeper documents fail |
| `graphql.max_complexity` | `3000` | admits a full page of the heaviest Console list query |
| `graphql.max_page_size` | `100` | configured page cap used by list resolvers (session listing rejects larger requests) |
| `graphql.timeout_secs` | `10` | per-request timeout |
| alias budget | `max_complexity` | counts aliased selections to bound response amplification |

Over-limit documents report `28110` (too deep) or `28111` (too complex) with the
configured limit, rather than the generic invalid-request `28100`.

## Errors

Responses use a single envelope:

```json
{
  "errors": [{
    "message": "localized text",
    "path": ["users"],
    "extensions": { "code": 28100, "kind": "validation", "requestId": "…", "traceId": "…" }
  }],
  "extensions": { "requestId": "…", "traceId": "…" }
}
```

- `code` is a stable numeric catalog key from `graphql/error-catalog.json` (the
  catalog also carries the `E<code>` fluent key); messages are localized to the
  request language and never expose internal details. Authentication step-up
  errors instead use the string codes `insufficient_user_authentication` or
  `insufficient_scope` with `acr_values`/`max_age` or `requiredScope`.
- `kind` groups codes into `validation`, `conflict`, `forbidden`, `not_found`,
  `unauthorized`, `gone`, `rate_limit`, and `internal`.
- `requestId` always correlates with `x-request-id` on the response and with
  audit facts. `traceId` appears only when a trusted trace context exists; it is
  never fabricated.
- Field-level validation failures appear in `extensions` of the corresponding
  error so clients can attach them to inputs.
- Guards and transactional authentication checks return the same standard
  authentication challenge, which is what lets a client complete MFA in the
  existing browser popup and continue.

## Management scope catalog

These 44 scopes are reserved, defined by the server, and regenerated into
`graphql/management-scopes.json`. `authentication` is the human requirement;
`machine` indicates whether client-credentials tokens may use the scope, always
subject to the client's live granted-scope ceiling.

| Scope | Authentication | Machine |
| --- | --- | --- |
| `management.user.read` | AAL2 | yes |
| `management.user.create` | AAL2 | yes |
| `management.user.update` | AAL2 | yes |
| `management.user.state` | AAL2 | yes |
| `management.user.revoke_access` | RECENT_AAL2 | yes |
| `management.session.read` | AAL2 | yes |
| `management.session.revoke` | AAL2 | yes |
| `management.credential.read` | AAL2 | yes |
| `management.credential.revoke` | RECENT_AAL2 | no |
| `management.credential.reset` | RECENT_AAL2 | no |
| `management.client.read` | AAL2 | yes |
| `management.client.create` | AAL2 | yes |
| `management.client.update` | AAL2 | yes |
| `management.client.state` | AAL2 | yes |
| `management.client.delete` | RECENT_AAL2 | no |
| `management.client.scope` | AAL2 | yes |
| `management.client_credential.read` | AAL2 | yes |
| `management.client_credential.create` | RECENT_AAL2 | no |
| `management.client_credential.rotate` | RECENT_AAL2 | no |
| `management.client_credential.revoke` | RECENT_AAL2 | no |
| `management.resource.read` | AAL2 | yes |
| `management.resource.write` | AAL2 | yes |
| `management.scope.read` | AAL2 | yes |
| `management.scope.write` | AAL2 | yes |
| `management.setting.read` | AAL2 | yes |
| `management.setting.write` | RECENT_AAL2 | no |
| `management.key.read` | AAL2 | yes |
| `management.key.create` | RECENT_AAL2 | no |
| `management.key.rotate` | RECENT_AAL2 | no |
| `management.key.revoke` | RECENT_AAL2 | no |
| `management.audit.read` | AAL2 | yes |
| `management.permission.read` | AAL2 | yes |
| `management.permission.write` | RECENT_AAL2 | no |
| `management.role.read` | AAL2 | yes |
| `management.role.write` | RECENT_AAL2 | no |
| `management.role_assignment.read` | AAL2 | yes |
| `management.role_assignment.write` | RECENT_AAL2 | no |
| `management.group.read` | AAL2 | yes |
| `management.group.write` | RECENT_AAL2 | no |
| `management.group_membership.read` | AAL2 | yes |
| `management.group_membership.write` | RECENT_AAL2 | no |
| `management.group_role.read` | AAL2 | yes |
| `management.group_role.write` | RECENT_AAL2 | no |
| `management.permission.delegate` | RECENT_AAL2 | no |

Read scopes read; write scopes change the definition or relationship. There is
no implicit read inheritance from a write scope, and no wildcard management
grant. Built-in roles are combinations of these exact entries; see
[Built-in definitions](authorization.md#built-in-definitions).

## Generated artifacts

The executable schema is the source of truth. Do not hand-edit exports.

| Artifact | Regenerate | Verify |
| --- | --- | --- |
| `graphql/schema.graphql` | `pnpm graphql:schema` | `pnpm graphql:check` |
| `graphql/management-scopes.json` | `pnpm scopes:catalog` | `pnpm scopes:check` |
| `graphql/error-catalog.json` | `pnpm errors:catalog` | `pnpm errors:check` |
| Console operation types | `pnpm graphql:codegen` | `pnpm typecheck:console` |
| Generated access metadata | `pnpm graphql:access` | `pnpm graphql:access:check` |

`pnpm graphql:schema` also regenerates the shared `@identity/graphql-access`
metadata from the SDL, because standard introspection does not expose custom
directives.

## Related pages

- [Authorization model](authorization.md) — principals, effective permissions,
  delegation, recovery, credential authority.
- [Protocol reference](protocol.md) — OAuth/OIDC endpoints, client policy,
  resource indicators, PAR.
- [Security](security.md) — password policy, MFA, sessions, browser windows.
