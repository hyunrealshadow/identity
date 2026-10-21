# Protocol reference

[Back to the project README](../README.md)

This reference describes Identity's OAuth/OIDC client policy, resource model,
pushed authorization requests, and HTTP APIs. Supported algorithms are advertised
through discovery and depend on the active keys and client metadata.

- [Client policy](#client-policy)
- [Resource indicators](#resource-indicators-rfc-8707)
- [Pushed authorization requests](#pushed-authorization-requests-rfc-9126)
- [HTTP endpoints](#http-endpoints)

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
setting, not dynamic registration metadata.
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

Resources are registered in the PostgreSQL `resource` table.
Each row has a unique `uri`, display `name`, JSON array of allowed `scopes`,
and `enabled` flag. Initialization registers `urn:identity:graphql` without
overwriting an existing row, including an administrator's disabled state.
Additional resources can be registered with SQL:

```sql
INSERT INTO resource (uri, name, scopes)
VALUES ('https://api.example.com/account', 'Account API', '["account.read"]'::jsonb);
```

The `scope` table is the supported scope catalog for each protocol. OpenID
Connect discovery reads rows with `protocol = 'openid_connect'`; `client_scope`
assigns the scopes a client may request. Custom scope names use OAuth scope-token
syntax and exact matching, and survive consent, token issuance, and refresh.
Add their definitions to `scope`, assign them through `client_scope`, and include
their names in the appropriate resource's `scopes` array. Custom resource
permissions require an explicit resource indicator and do not default to the
built-in GraphQL API. Resource registration does not add scope definitions or
provide an administration API. Client scope assignments and consent still apply.
Resources identify target APIs, while scopes define permissions. Each resource
is associated with the scopes it accepts.

Consent pages use the scope table's `display_name` and `description`. Its
`descriptions` JSONB object maps language tags such as `zh-CN` and `en-US` to
localized descriptions; a missing translation falls back to `description`.

### Request and select targets

Authorization and token requests accept repeated `resource` parameters, for
example `resource=https%3A%2F%2Fapi.example.com%2Faccount&resource=urn%3Aidentity%3Agraphql`.
Request Objects accept a single URI string or a nonempty array of URI strings.
Device authorization also accepts and persists resource indicators. Values must
be absolute, fragment-free URIs; matching preserves the exact spelling. Query
components are accepted. Resource identifiers are never fetched.

Explicit authorization targets must be enabled and collectively cover the
requested scopes. Code and refresh exchanges may select a subset of the original
targets; access-token scopes are reduced to those allowed by the selected targets.
JWT access-token `aud` contains those targets, while ID Token `aud` remains the
client ID. Refresh tokens retain the original resource grant and scopes, allowing
a subsequent refresh for another originally authorized resource. An explicit
refresh `scope` still narrows the grant under RFC 6749.

Multi-audience access tokens include only scopes allowed by every selected
resource. Protocol controls (`openid` and `offline_access`) remain grant context
and are retained separately from resource permissions. If no requested resource
permission is common to all targets, the token
request returns `invalid_target` without consuming the grant. Authorization-code
grants can still cover distinct permissions at distinct resources; clients can
request a separate access token for each resource. This scope restriction does
not prevent bearer-token forwarding between audiences: multi-audience tokens
still require mutual trust between resource servers, as described in
[RFC 8707 Section 3](https://www.rfc-editor.org/rfc/rfc8707.html#section-3).

Unknown, disabled, malformed, out-of-grant, or incompatible targets return
`invalid_target`; failed target validation does not consume the code or refresh
token. Omitting targets reuses the grant's targets. Legacy grants without resource
indicators retain their audience behavior and may select a registered target at
the token endpoint; the resulting refresh token records that selection. API-scope
authorization requests require an explicit resource indicator. API-scope token
requests without indicators resolve the built-in GraphQL resource through the
registry, so disabling it also blocks new tokens targeting it.

## Pushed authorization requests (RFC 9126)

### Submit and consume a request

Clients POST authorization parameters as `application/x-www-form-urlencoded` to
`/oauth2/par`, using their token-endpoint authentication method. Public clients
must have `allow_public_client_flow` enabled and satisfy the applicable PKCE rules.
The endpoint validates client policy, redirect URI, scopes, resource indicators,
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
requests cannot reuse a reference. Current client policy is checked again before
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
| GET, POST | `/oauth2/userinfo` | UserInfo |
| GET, POST | `/oauth2/logout` | RP-initiated logout |
| GET | `/oauth2/check_session` | Session management iframe |
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

`/graphql` provides authenticated account, security, and session operations.
It validates bearer tokens and resource audience, enforces API scopes, and
requires recent authentication for sensitive operations. It has configurable
query depth, complexity, pagination, and timeout limits. Its listener may be
shared with the public API or bound separately.

### Internal workload API

The separate internal listener requires workload authentication for every
endpoint:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/internal/installation/status` | Installation status |
| POST | `/internal/installation` | Initialize the installation |
| GET | `/internal/workloads/self/runtime-configuration` | Login runtime configuration and current OAuth credential |
| GET | `/internal/observability/metrics` | Optional observability pipeline metrics |
