# Identity

Identity is an OAuth 2.0 authorization server and OpenID Connect Provider built
with Rust, Salvo, and PostgreSQL. A separate React/TanStack Start application
provides installation, sign-in, consent, device verification, and account
management.

The repository includes protocol tests and an OpenID Foundation conformance
runner. Conformance results depend on the selected profile, build features,
client configuration, and deployment; the presence of the runner does not
establish certification.

## Capabilities

| Area | Current coverage |
| --- | --- |
| OAuth grants | Authorization code, refresh token, client credentials, and device authorization |
| OIDC flows | Authorization code, implicit, and hybrid; query, fragment, and Form Post response modes |
| Discovery | OIDC discovery, OAuth authorization server metadata (RFC 8414), and public JWKS |
| Tokens | Signed JWT access tokens and ID Tokens; encrypted ID Tokens; refresh rotation and replay handling |
| Token lifecycle | Revocation (RFC 7009) and authenticated introspection (RFC 7662) |
| Resource indicators | RFC 8707: registered resource URIs, multiple audiences, resource-specific scopes, and refresh grant binding |
| Pushed authorization | RFC 9126: authenticated back-channel requests, expiring client-bound references, and one-time consumption |
| Client registration | Dynamic registration (RFC 7591), plus read, full replacement update, and delete (RFC 7592) |
| Client authentication | `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, and public clients using `none` where permitted |
| Authorization requests | PKCE S256, nonce, consent, account selection, silent requests, reauthentication, `max_age`, `acr_values`, and claims requests |
| Request objects | Signed, unsigned, and encrypted objects; `request` and pre-registered `request_uri` |
| UserInfo | JSON, signed, and encrypted responses; scope-filtered profile, email, address, and phone claims |
| Subjects | Public and pairwise subject identifiers, including sector identifier validation |
| Logout | RP-initiated, front-channel, and back-channel logout; OP session iframe |
| Authentication | Password sign-in, TOTP MFA, single-use recovery codes, and AAL1/AAL2 authentication context |
| Account management | Profile, username, email, password, TOTP enrollment/disable, and recovery-code regeneration |
| Sessions | Multiple signed-in accounts, session listing, individual revocation, and revocation of other sessions |
| Operations | Ordered migrations, runtime settings refresh, built-in Login credential rotation, health checks, and optional OTLP observability |

Supported algorithms are advertised through discovery. Signing capabilities
also depend on the active keys and client metadata.

### Protocol behavior and limits

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

Web redirect URIs require HTTPS, with an explicit `http://localhost`
development exception. Native loopback IP redirects may use HTTP. The Web
localhost exception is a deliberate deviation from RFC 9700 §2.6.
OIDC clients with multiple registered redirect URIs must supply
`redirect_uri`.

Introspection requires confidential client authentication and discloses only
tokens issued to the authenticated client. Unknown, expired, revoked, or
unauthorized tokens return only `{"active":false}`. A token type hint is
optional and does not restrict which supported token formats are checked.

Dynamic registration is disabled by default through the database runtime
setting `openid_connect.dynamic_registration.enabled`. When enabled outside
conformance mode, the registration endpoint is open; a fixed initial access
token is supported only for conformance harnesses. Management requests use the
issued registration access token.

Client updates replace metadata rather than merge it. They require a matching
`client_id`; an optional `client_secret` must match the current secret.
Server-managed registration fields are rejected. Updates rotate the secret
for confidential clients and return its replacement, preserving the client
ID, registration access token, and existing authorization records. Built-in
clients cannot update their registration through this endpoint.

Device authorization uses a 10-minute request lifetime and a 5-second polling
interval by default, configurable through
`openid_connect.device_authorization`. Polling enforces pending, slow-down,
expiry, denial, and single-use issuance. Device-issued tokens follow the device
authorization relation rather than the browser session that approved it.
User-code lookup does not currently have a dedicated rate limiter.

### Resource indicators (RFC 8707)

Resources are registered in the PostgreSQL `resource` table.
Each row has a unique `uri`, display `name`, JSON array of allowed `scopes`,
and `enabled` flag. Initialization registers `urn:identity:graphql` without
overwriting an existing row, including an administrator's disabled state.
Additional resources can be registered with SQL:

```sql
INSERT INTO resource (uri, name, scopes)
VALUES ('https://api.example.com/account', 'Account API', '["account.read"]'::jsonb);
```

Resource scopes currently use the supported scope catalog; this table does not
add custom scope names or provide an administration API. Client scope assignments
and consent still apply. The registry follows the resource/scope separation used
by [Duende IdentityServer](https://docs.duendesoftware.com/identityserver/fundamentals/resources/isolation/).

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

Unknown, disabled, malformed, out-of-grant, or incompatible targets return
`invalid_target`; failed target validation does not consume the code or refresh
token. Omitting targets reuses the grant's targets. Legacy grants without resource
indicators retain their audience behavior and may select a registered target at
the token endpoint; the resulting refresh token records that selection. API-scope
authorization requests require an explicit resource indicator. API-scope token
requests without indicators resolve the built-in GraphQL resource through the
registry, so disabling it also blocks new tokens targeting it.

### Pushed authorization requests (RFC 9126)

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
to match client registration. Production deployments should use an HTTPS issuer.

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
| GET, PUT, DELETE | `/oauth2/register/{client_id}` | Manage a dynamic client |
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

`/graphql` provides authenticated account, security, and session operations.
It validates bearer tokens and resource audience, enforces API scopes, and
requires recent authentication for sensitive operations. It has configurable
query depth, complexity, pagination, and timeout limits. Its listener may be
shared with the public API or bound separately.

The separate internal listener requires workload authentication for every
endpoint:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/internal/installation/status` | Installation status |
| POST | `/internal/installation` | Initialize the installation |
| GET | `/internal/workloads/self/runtime-configuration` | Login runtime configuration and current OAuth credential |
| GET | `/internal/observability/metrics` | Optional observability pipeline metrics |

## Architecture

```text
src/
  domain/          Domain models, protocol types, and repository contracts
  application/     Use cases, authentication, and OAuth/OIDC services
  infrastructure/  SeaORM repositories, cryptography, settings, and observability
  web/             Salvo handlers, middleware, GraphQL, and protocol HTML
  boot/            Configuration, application assembly, and listener startup
migration/          Ordered schema and data migrations
apps/login/         React/TanStack Start Login application and backend
assets/             Fluent translations, Tera templates, and error-page styles
conformance/        Docker-based OIDC conformance runner and test plans
deploy/             Docker Compose and Helm deployment examples
docs/               Design notes, reviews, and architecture decisions
```

Domain and application code depend on repository contracts rather than
SeaORM entities. Infrastructure supplies persistence and other adapters.
Application services also perform protocol-related remote document retrieval.

The Login application owns the browser UI. Identity renders protocol-required
HTML such as Form Post, the session iframe, front-channel logout, and terminal
error pages. Login and consent use native HTML forms with progressive
enhancement. The UI and localized service errors support English and Simplified
Chinese.

## Local development

### Prerequisites

- A Rust toolchain that supports edition 2024 and the locked dependencies.
  The deployment build currently uses Rust 1.96.
- PostgreSQL and a database/user with permission to run migrations.
- OpenSSL development libraries and the platform's native build tools;
  the Linux build installs `pkg-config` and `libssl-dev`.
- Node.js and pnpm for the Login application and error-page CSS.
  The deployment build uses Node.js 22 and pnpm 11.24.0.

Run from the repository root so configuration, templates, and translations can
be found. The following examples use a POSIX shell; in PowerShell, set
variables with `$env:NAME = "value"`.

### Start Identity

Create the database and configure its connection string. Generate a workload
token and a separate Login cookie sealing secret:

```sh
export DATABASE_URL='postgres://identity:replace-with-password@localhost:5432/identity'
export IDENTITY_WORKLOAD_TOKEN="$(openssl rand -base64 32)"
export IDENTITY_LOGIN_SESSION_SECRET="$(openssl rand -base64 32)"
export IDENTITY_PUBLIC_APP_URL='https://localhost:3000'

cargo run --locked --bin identity
```

The default environment reads [config/development.yaml](config/development.yaml).
It starts the public API at `https://localhost:5150` and the internal API at
`https://localhost:5151`, generating a local TLS certificate when needed.
In this configuration, GraphQL and `/health` share the public listener.

### Start Login and install

In a second terminal, provide the same workload token and cookie sealing
secret, then run:

```sh
pnpm install --frozen-lockfile
pnpm dev:login
```

Open `https://localhost:3000` and complete installation. Trust the local
development certificates in your browser. The development Login server accepts
Identity's local self-signed certificate; production retains TLS validation.

Installation accepts the administrator's username, email, password, Identity
domain, Login application URL, and signing-key algorithm. Use
`https://localhost:5150` as the Identity URL and
`https://localhost:3000` as the Login application URL for the default setup.
Installation creates the administrator, signing material, built-in Login
client, and runtime state in a database transaction.

The application origin is stored as `app.login_domain`; Identity derives
the login, consent, and device UI URLs from it. The issuer comes from
`app.domain`. A complete `install` section in the service configuration can
also initialize an uninstalled database automatically.

### Build

```sh
cargo build --locked --release --bin identity
pnpm build:error-css
pnpm build:login
pnpm --filter login start
```

Login's production server uses Nitro. See
[apps/login/README.md](apps/login/README.md) for its transport, environment
variables, and health behavior.

## Configuration and deployment

Identity loads `config/{environment}.yaml`, selected by `APP_ENV`
(`RUST_ENV` is a fallback; the default is `development`). YAML templates can
read environment variables with `get_env`. Variables affect fields only
where the selected template uses them: `PORT` and `HOST`, for example, are
not universal overrides. The repository ships development, test, and
conformance configurations; production examples are under `deploy/`.

Listener addresses, TLS, database access, workload authentication, GraphQL
limits, and observability belong to startup configuration. Installed domains,
client metadata, password-hashing settings, and OAuth runtime settings are stored in
PostgreSQL. Runtime settings refresh periodically (30 seconds by default).

Login's main environment variables are:

| Variable | Purpose |
| --- | --- |
| `IDENTITY_API_URL` | Browser-visible Identity URL; defaults to `https://localhost:5150` |
| `IDENTITY_BACKCHANNEL_API_URL` | Server-side protocol and interactive API calls |
| `IDENTITY_BACKCHANNEL_GRAPHQL_URL` | Server-side GraphQL calls |
| `IDENTITY_INTERNAL_API_URL` | Internal workload API; defaults to `https://localhost:5151` |
| `IDENTITY_WORKLOAD_TOKEN_FILE` / `IDENTITY_WORKLOAD_TOKEN` | File-based workload credential or inline development token |
| `IDENTITY_LOGIN_SESSION_SECRET` | Cookie sealing secret, shared across Login replicas |
| `IDENTITY_PUBLIC_APP_URL` | Public HTTPS origin of the Login application |

Identity supports direct TLS termination or TLS termination by a trusted
upstream proxy. Its configured public URL must use HTTPS in both modes.
Upstream mode uses `server.tls.trusted_proxies` to determine who may supply
forwarded HTTPS and client-IP headers. Explicit private HTTP callers can be
listed separately in `server.tls.direct_http_clients`.

Login uses HTTPS for internal and backchannel calls by default. Private HTTP
requires the corresponding `IDENTITY_INTERNAL_API_ALLOW_HTTP=true` or
`IDENTITY_BACKCHANNEL_ALLOW_HTTP=true` opt-in. Keep the internal listener off
public ingress. It accepts configured static workload tokens or verified
Kubernetes projected ServiceAccount tokens.

The built-in Login client secret is stored in PostgreSQL and fetched into
Login's memory through the internal API. Identity rotates it after 60 days,
gives the new generation a 90-day lifetime, and retains the previous generation
for a 24-hour overlap. The workload credential and shared cookie sealing
secret are configured independently.

Deployment guides:

- [Docker Compose and credential lifecycle](deploy/README.md)
- [Helm chart](deploy/helm/identity/README.md)
- [Kubernetes examples](deploy/kubernetes/README.md)

## Database lifecycle

With `database.auto_migrate: true`, startup applies the ordered migrator.
Startup also ensures built-in settings and scopes. The `oidc-conformance`
feature adds fixed test-data seeding at startup; use that build with an isolated
conformance database. Conformance HTTP routes additionally require
`APP_ENV=conformance`.

The `migration` crate is the schema history; current SeaORM entities are
under `src/infrastructure/database/entity`. A schema change must add an
ordered migration and update the corresponding entities. Historical
migrations must remain independent of current entity definitions.

Runtime schema synchronization is not used. PostgreSQL-specific indexes and
constraints remain explicit migration statements where portable entity
metadata cannot represent them.

## Observability and health

Identity supports structured console logs and optional OTLP/HTTP export of
traces, logs, and business/audit events. Login has a separate opt-in OTLP
pipeline. Trace trust is configured independently from proxy/IP trust;
browser-provided trace context is treated as untrusted.

The pipelines use bounded queues. Export failures and drops are exposed through
optional self-metrics rather than blocking authentication. PII can be
pseudonymized using a configured HMAC key, with redaction as the fallback.
Audit storage permissions and retention are deployment responsibilities.

Identity's configurable `/health` endpoint checks database connectivity.
Login exposes `/health/live` and `/health/ready`; after installation,
readiness requires usable runtime configuration and a current OAuth credential.

See [observability coverage](docs/observability-coverage.md),
[observability design](docs/observability-design.md), and the
[deployment guide](deploy/README.md#observability).

## Tests and conformance

```sh
cargo test --workspace --locked
cargo check --workspace --all-targets --features oidc-conformance --locked
cargo fmt --all -- --check
pnpm --filter login test
```

The conformance harness uses Docker Compose, `uv`, and Playwright:

```sh
cd conformance
uv sync
uv run playwright install chromium
uv run python run.py --profile basic --exit-on-failure
```

Available profiles: `basic`, `implicit`, `hybrid`, `config`,
`formpost-basic`, `formpost-implicit`, `formpost-hybrid`,
`third-party-init`, `rp-init-logout`, `session`, and `backchannel`.

The harness image enables `oidc-conformance` and `allow-none-alg`.
For a manually started conformance server, set `APP_ENV=conformance` and
build with those features. Conformance-only auto-login and fixture behavior
are isolated from the default production build. `allow-none-alg` permits
unsigned ID Tokens for conformance scenarios; unsigned request objects have
separate protocol handling.

Runner outcomes include warnings, skips, and review results. Inspect the
profile results before describing a deployment as conformant.
See [conformance/README.md](conformance/README.md) for runner options and
environment variables.
