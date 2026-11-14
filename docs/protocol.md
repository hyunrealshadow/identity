# Protocol reference

[Back to the project README](../README.md)

This reference describes Identity's OAuth/OIDC client policy, resource model,
pushed authorization requests, and HTTP APIs. Supported algorithms are advertised
through discovery and depend on the active keys and client metadata.

- [Client policy](#client-policy)
- [Resource indicators](#resource-indicators-rfc-8707)
- [Pushed authorization requests](#pushed-authorization-requests-rfc-9126)
- [Identifiers](#identifiers)
- [HTTP endpoints](#http-endpoints)

## Identifiers

Object identifiers leave the service as Global IDs: unpadded base64url of
`<Type>:` followed by the 16 UUID bytes. GraphQL `ID` values, the OAuth
`client_id`, a public `sub` (`User`, or `Client` for machine tokens), access
and logout token `jti` values, JWK `kid` values (`KeyJwk`), and Passkey
challenge IDs all use this form; raw UUIDs are rejected. Pairwise subjects
remain unlinkable hashes. `sid` is not a Global ID: it is a purpose-bound,
data-protected session handle that browsers also present as a credential.
Storage, internal records, and telemetry keep plain UUIDs; conversion happens
only at the service boundary.

## Client policy

### OAuth version and PKCE

Public clients must use PKCE S256 for authorization code requests in both
implemented OAuth versions. OAuth 2.1 also requires PKCE S256 for confidential
clients, including OIDC requests that carry a nonce. OAuth 2.0 confidential
clients may omit PKCE. These rules depend on the client's configured protocol
version and authentication methods.

The global `openid_connect.oauth_version` selects the default OAuth `"2.0"` or
`"2.1"` rules and defaults to `"2.0"`. Clients inherit this live setting unless
`OpenIdConnectClientSettings.oauth_version` explicitly overrides it. Existing
explicit client versions remain effective. The client override is an internal
setting, not dynamic registration metadata: administrators set it through the
instance GraphQL client settings, and clearing it makes the client inherit the
global value again.
Selecting it does not imply coverage of every OAuth extension.
OAuth 2.1 rejects response types that return an access token from the
authorization endpoint.

### Public clients and grant permissions

Public-client flows also require the per-client
`OpenIdConnectClientSettings.allow_public_client_flow` setting (default `false`).
Registering authentication method `none` alone does not enable unauthenticated
access. Dynamic registration with `token_endpoint_auth_method: "none"` enables
this setting; administrators can disable it afterward. Disabling it blocks
credential-free token, device authorization, and revocation requests, including
revocation of previously public tokens. Clients with both `none` and confidential
authentication methods can still use their registered confidential methods.

Client grant permissions are enforced. Registration without `grant_types`
defaults to `authorization_code`; an explicit empty list allows no grants.
Clients that need refresh tokens, implicit flows, client credentials, or the
device grant must be configured for those grants.

### Redirect URIs

Web redirect URIs require HTTPS, with an explicit `http://localhost`
development exception. Native loopback IP redirects may use HTTP. The Web
localhost exception is a deliberate deviation from RFC 9700 §2.6.
OIDC clients with multiple registered redirect URIs must supply
`redirect_uri`.

### Introspection

Introspection requires confidential client authentication and discloses only
tokens issued to the authenticated client. Unknown, expired, revoked, or
unauthorized tokens return only `{"active":false}`. A token type hint is
optional and does not restrict which supported token formats are checked.

### Dynamic registration

Dynamic registration is disabled by default through the database runtime
setting `openid_connect.dynamic_registration.enabled`. When enabled outside
conformance mode, the registration endpoint is open; a fixed initial access
token is supported only for conformance harnesses. Management requests use the
issued registration access token.

Client management uses `/oauth2/clients/{client_id}`. Registration responses
return this address in `registration_client_uri`; clients should use that URI
for subsequent read, replacement update, and delete requests.

Client updates replace metadata rather than merge it. They require a matching
`client_id`; an optional `client_secret` must match the current secret.
Server-managed registration fields are rejected. Updates rotate the secret
for confidential clients and return its replacement, preserving the client
ID, registration access token, and existing authorization records. Built-in
clients cannot update their registration through this endpoint.

### Device authorization

Device authorization uses a 10-minute request lifetime and a 5-second polling
interval by default, configurable through
`openid_connect.device_authorization`. Polling enforces pending, slow-down,
expiry, denial, and single-use issuance. Device-issued tokens follow the device
authorization relation rather than the browser session that approved it.
User-code lookup does not currently have a dedicated rate limiter.

### Token claims

Access tokens are RFC 9068 JWTs (`typ: at+jwt`) carrying `iss`, `sub`, `aud`,
`exp`, `iat`, `jti`, `client_id`, `scope`, and, for user tokens, the OIDC
authentication claims `sid`, `auth_time`, `acr`, and `amr`. Authorization
snapshots used for revocation stay server-side, keyed by `jti`: Identity
checks them against live authorization on every GraphQL, UserInfo, and
introspection request. The OIDC `claims` request parameter is likewise kept
with the token record for UserInfo rather than copied into the JWT. External
resource servers should rely on `scope`,
`aud`, and `client_id`, and use introspection when they need live state.

Per-client settings `include_scoped_claims_in_id_token` and
`include_scoped_claims_in_access_token` default to `false`. Enabling them adds
standard user claims covered by the granted `profile`, `email`, `phone`, and
`address` scopes to tokens issued at the token endpoint. Machine access tokens
have no user claims. UserInfo remains available independently; implicit-flow
ID Token claim handling follows its own flow rules.

### Browser access and CORS

The internal per-client setting `cors_enabled` defaults to `false`. When enabled,
client registration persistence derives allowed origins from the client's
registered HTTP(S) redirect URIs. These origins are stored in
`client_openid_connect_cors_origin` and loaded into a shared origin allowlist by
the runtime settings refresher.

CORS covers discovery, JWKS, token, revocation, PAR, dynamic registration and
registration management, and UserInfo endpoints. Preflight requests permit only
the endpoint's declared methods and the `Authorization` and `Content-Type`
headers. The authorization endpoint does not enable CORS; use browser navigation
for authorization requests.

## Resource indicators (RFC 8707)

### Register resources and scopes

The PostgreSQL `resource` table identifies each target API by a unique `uri`,
display `name`, `enabled` state and UUID `version` for optimistic locking.
The `scope` table owns the permission definitions: `scope.resource_id` references
`resource.oid`. A scope's `code` is unique within its resource; the same code may
exist at another resource without conveying any authority there. Resources do
not store a second JSON scope list or an authorization-mode setting.

`openid`, `profile`, `email`, `address`, `phone` and `offline_access` are global
protocol scopes with a NULL resource reference. They are not role permissions.
There is no scope `protocol` column. The built-in GraphQL API resource is
`urn:identity:graphql`.

GraphQL exposes `createResource`, `createScope`, scope metadata updates and scope
state changes. `createScope` requires a resource global ID. Resource ownership
and code cannot be changed after creation. `client_scope` and `role_permission`
reference the same canonical scope IDs; there is no separate permission catalog.
See the [executable schema](../graphql/schema.graphql) for inputs and access
requirements.

Clients receive an explicit scope ceiling through `client_scope`. Each row bounds
what the client may request on behalf of a user; `client_granted` additionally
grants the scope to the client itself for the client-credentials grant and
machine management access. Public dynamic
registration can request protocol and intrinsic account self-service scopes;
it cannot declare arbitrary API permissions. Registration metadata updates retain
existing exact scope IDs and cannot turn delegated user authority into a new
client-credentials grant.

Request selectors such as `account.*`, `session.*` and `management.*` expand only
against registered scopes at the requested resource. A selector can be used at
any hierarchy level, includes descendants rather than the prefix itself, and
cannot create a permission. Persistent assignments contain concrete scope IDs,
not wildcard definitions.

Scope display fields are `name`/`names` and `description`/`descriptions`. The
JSONB maps use language tags as keys and translations as string values. Display
language and fallback are selected by the viewing application; definitions have
no `default_locale`. Names and descriptions never participate in authorization.

### Request and select targets

Authorization and token requests parse repeated `resource` parameters. Request
Objects accept a URI string or a nonempty array of URI strings. Exact duplicate
URIs are deduplicated. Values must be absolute and fragment-free; matching
preserves the exact spelling, query components are accepted, and identifiers are
never fetched.

API-scope authorization requests require an explicit resource indicator. Custom
API scopes always require their owning resource. Self-service or management
scopes at token endpoints may resolve the built-in GraphQL resource when no
indicator is supplied. A protocol-only login may omit a resource; its protocol
scopes are still checked against the client's explicit assignments.

Custom API user authorization uses code flow with S256 PKCE and one target API.
Combining custom APIs or mixing a custom API with GraphQL is rejected. A flat
scope string cannot disambiguate equal codes at different resources; it must
never transfer one resource's grant to another resource.

Requests must fit the client's exact scope IDs at the target resource. User
requests are additionally limited by effective direct-role and group-role
permissions; intrinsic account/session self-service does not require any
management permission. Machine requests use the client's own scope ceiling without
human role membership, MFA or an extra client-management grant.

Code and refresh exchanges cannot expand their original resource grant. JWT
access-token `aud` identifies the selected API, while ID Token `aud` remains the
client ID. All six protocol scopes remain separate from resource permission
intersection. Explicit refresh `scope` may narrow the grant under RFC 6749.
Device authorization records resource indicators but rejects custom business
RBAC and management issuance paths in the current implementation.

Unknown, disabled, malformed, out-of-grant or incompatible targets are rejected.
Failed target validation does not consume the code or refresh token. Scope
ownership, client ceiling and live user authority are checked again at issuance,
refresh, introspection and online bearer validation.

## Pushed authorization requests (RFC 9126)

### Submit and consume a request

Clients POST authorization parameters as `application/x-www-form-urlencoded` to
`/oauth2/par`, using their token-endpoint authentication method. Public clients
must have `allow_public_client_flow` enabled and satisfy the applicable PKCE rules.
The endpoint validates client registration, redirect URI, scopes, resource indicators,
and Request Objects before returning HTTP 201 with `request_uri` and `expires_in`.
It does not start login or consent interactions. Requests larger than 64 KiB are
rejected. A `request_uri` parameter cannot be pushed.
Plain form requests must explicitly include `client_id`; client authentication
does not supply this authorization parameter. With `request`, client identification
may instead come from the authentication method and verified Request Object.

The browser then opens `/oauth2/authorize?client_id=CLIENT_ID&request_uri=REFERENCE`.
Additional recognized authorization parameters are rejected. References use
256 bits of randomness and are bound to the authenticated client. PostgreSQL stores
their SHA-256 digest and authorization parameters in `client_authorization.data`,
using type `pushed_authorization_request`, without client credentials. A partial
unique index covers the reference digest. `completed_at` records consumption;
the existing expiry and revocation fields also apply.
Consumption atomically checks the client, expiry, and unused state; concurrent
requests cannot reuse a reference. Current client registration is checked again before
authorization proceeds.

### Runtime policy and Request Objects

The runtime setting `openid_connect.pushed_authorization` defaults to
`{"request_ttl_seconds":90,"require_pushed_authorization_requests":false}`.
Lifetime must be between 1 and 600 seconds. Setting the global requirement or
client metadata `require_pushed_authorization_requests` to `true` requires PAR
for that client. Dynamic registration and replacement updates accept this metadata.
OIDC discovery and OAuth server metadata publish the PAR endpoint and global
requirement. Expired and consumed rows can be removed periodically using SQL.

Signed or encrypted Request Objects use the existing verification rules; when
`request` is supplied, only client identification and authentication parameters
may accompany it.
PAR rejects invalid UTF-8 after form decoding, and Request Objects cannot contain
nested `request` or `request_uri` claims. JWT client assertions accept the issuer,
token endpoint, or
PAR endpoint as their audience for PAR authentication. Redirect URIs still need
to match client registration. Identity requires its configured public URL to
use HTTPS.

## HTTP endpoints

Paths below are relative to the service's public origin.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/.well-known/openid-configuration` | OIDC discovery |
| GET | `/.well-known/oauth-authorization-server` | OAuth authorization server metadata |
| GET | `/.well-known/keys` | Public JWKS |
| GET, POST | `/oauth2/authorize` | Authorization requests |
| POST | `/oauth2/par` | Push an authorization request |
| POST | `/oauth2/token` | Token issuance and refresh |
| POST | `/oauth2/revoke` | Token revocation |
| POST | `/oauth2/introspect` | Token introspection |
| POST | `/oauth2/device` | Start device authorization |
| POST | `/oauth2/register` | Create a dynamic client |
| GET, PUT, DELETE | `/oauth2/clients/{client_id}` | Manage a dynamic client |
| GET, POST | `/openid/userinfo` | UserInfo |
| GET, POST | `/openid/logout` | RP-initiated logout |
| GET | `/openid/check_session` | Session management iframe |
| GET | `/oauth2/initiate_login` | Third-party initiated login |
| GET | `/oauth2/continue` | Resume an authorization interaction |
| GET, POST | `/oauth2/consent` | Consent JSON API |
| POST | `/oauth2/device/login` | Begin device verification interaction |

For an issuer containing a path, RFC 8414 metadata places that path **after**
the well-known suffix: issuer `https://example.com/tenant` uses
`https://example.com/.well-known/oauth-authorization-server/tenant`.
Deployment routing must preserve the configured issuer and endpoint URLs.

The interactive JSON API lives under `/api/auth`. Login's backend forwards
session state through `X-Sessions` and CSRF state through `X-CSRF-Token`.
The browser returns to `/oauth2/continue` after login or consent.

### GraphQL

`/graphql` provides account self-service, security, sessions and functional
instance-management queries and named mutations. It validates bearer identity,
resource audience, current scope authority and the required authentication level.
Machine principals do not acquire a human identity or satisfy human-only
operations.

Operation entry points and protected relationship fields publish their access
requirements through repeatable `@access` directives, which drive the shared
frontend preflight. Live ownership, delegation
and transaction checks remain authoritative; `runtime: true` marks requirements
that cannot be proved from token contents alone. Guards and transaction-level
authentication failures return the same standard authentication challenge, so
clients can use the existing session and complete MFA in a browser popup.

Input validators, query depth, complexity, pagination and timeout limits apply.
The GraphQL listener may be shared with the public API or bound separately.

### Internal workload API

The separate internal listener requires workload authentication for every
endpoint:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/internal/installation/status` | Installation status |
| POST | `/internal/installation` | Initialize the installation |
| GET | `/internal/workloads/self/runtime-configuration` | Login runtime configuration and current OAuth credential |
| GET | `/internal/observability/metrics` | Optional observability pipeline metrics |
