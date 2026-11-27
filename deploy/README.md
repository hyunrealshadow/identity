# Deployment

This directory contains two supported deployment paths:

- `docker-compose.yml` for a single-host SIT deployment.
- `helm/identity` for a replicated Kubernetes deployment.

Both paths keep the built-in Login OAuth client secret in PostgreSQL. Identity
rotates that secret and Login fetches the current generation from the internal
runtime-configuration API. No OAuth client secret is stored in an environment
variable, Compose secret, Kubernetes Secret, or per-replica volume.

## Trust and credential model

| Purpose | Docker Compose | Kubernetes |
| --- | --- | --- |
| Login & Console authenticate to Identity | Separate static workload token files | Separate projected ServiceAccount JWTs |
| Login cookie encryption | Shared `IDENTITY_LOGIN_SESSION_SECRET` | Shared Kubernetes Secret |
| Built-in Login OAuth client secret | PostgreSQL; fetched and refreshed in memory | PostgreSQL; fetched and refreshed in memory |
| Identity TLS | Compose secret files | Existing TLS Secret |
| Login & Console TLS | Compose secret files | Optional existing TLS Secrets or upstream proxy |

The workload credential and the OAuth client secret have separate lifecycles.
Rotating a workload credential changes who may call the internal API;
Identity's scheduled rotation changes the Login OAuth credential returned by
that API. The latter does not require a rollout. Console uses a public OAuth
client with no client secret.

## Password security checks

The range password check requires HTTPS egress to `api.pwnedpasswords.com` or a
trusted compatible service configured through `IDENTITY_PWNED_PASSWORDS_URL`.
Timeouts fail closed; no complete password or complete hash is transmitted.

The persisted typed setting `auth.password.breached_check_enabled` defaults to
`true`. An explicit `false` skips the external check for installation, user
creation, and password changes. Local password rules and hashing remain in
effect. The setting uses the existing runtime settings refresh mechanism.

## Docker Compose

The Compose deployment runs PostgreSQL, Identity, Login, and Console. Identity
runs with `APP_ENV=production` and reads its configuration from the mounted
`deploy/config/identity.compose.yaml`. It uses three listeners: public protocol
and GraphQL API (`5150`), internal workload API (`5151`), and health (`8081`).
Only the public listener (`5150`), Login (`3000`), and Console (`8080`) are
published on the host. Login and Console reach Identity through the private
Compose service name rather than the public DNS name.

1. Copy `deploy/.env.example` to `deploy/.env` and replace both secrets.
2. Create distinct workload tokens (at least 32 random characters each) at
   `deploy/secrets/login-workload-token` and
   `deploy/secrets/console-workload-token`, for example with
   `openssl rand -base64 32`. Reusing the same token across workloads is
   rejected.
3. Place the Identity server certificate, private key, and issuing CA at
   `deploy/secrets/identity.crt`, `deploy/secrets/identity.key`, and
   `deploy/secrets/identity-ca.crt`.
4. Start the stack from the repository root:

   ```sh
   docker compose --env-file deploy/.env -f deploy/docker-compose.yml up --build -d
   ```

The default Identity, Login, and Console origins are
`https://identity.localhost:5150`, `https://identity.localhost:3000`, and
`https://identity.localhost:8080`. Compose mounts the supplied certificate into
all three web containers, so it must contain `identity.localhost` and `server`
as DNS SANs. Modern browsers resolve the reserved `.localhost` suffix to
loopback, while Compose resolves the same name through the service network
alias. If a real DNS name is used, it must resolve from both the browser and the
Login and Console containers.

When completing `/install`, enter `https://identity.localhost:8080` as the
Console URL without `/console`; Identity stores `https://identity.localhost:8080/console`
and exposes `/graphql` on the public `5150` listener. Before installation
completes, `console` waits for valid runtime configuration and remains
unhealthy; once `/install` finishes, it starts Nginx automatically and serves
Console at `https://identity.localhost:8080/console`.

All Login replicas must receive the same session secret. Scaling Login does
not create per-instance OAuth secrets:

```sh
docker compose --env-file deploy/.env -f deploy/docker-compose.yml up -d --scale login=3
```

The Login image runs `node production-server.mjs` directly, and
neither the image, Compose, nor the chart sets `NODE_ENV`. The bundle is already
the production build produced by `pnpm build:login`; add `NODE_ENV=production`
through the deployment environment only when a dependency needs to branch on it.

### TLS terminated by an upstream proxy

To run the Identity, Login, and Console containers over HTTP behind a reverse
proxy, add the upstream override:

```sh
docker compose --env-file deploy/.env \
  -f deploy/docker-compose.yml \
  -f deploy/docker-compose.upstream.yml \
  up --build -d
```

The override uses the Compose `!override` merge tag and therefore requires
Docker Compose 2.24.4 or newer.

Set `IDENTITY_TRUSTED_PROXY` in `deploy/.env` to the CIDR from which the reverse
proxy connects to the Identity container. Set `IDENTITY_DIRECT_HTTP_CLIENT` to
the Login container IP or its private Docker network CIDR. The former may
supply forwarded HTTPS metadata; the latter may call the public and GraphQL
APIs directly over HTTP. Do not use a public client address range. The public
issuer, Login, and Console addresses entered in `/install` must remain HTTPS
URLs. These addresses are stored in database settings, not deployment
environment variables.

The override removes all application TLS certificate and CA mounts, switches
every Login-to-Identity and Console-to-Identity call to the private HTTP
service ports (`IDENTITY_CONSOLE_TLS_ENABLED=false`,
`IDENTITY_INTERNAL_API_ALLOW_HTTP=true`), and changes the health checks to HTTP.
Route the public issuer's protocol paths and `/graphql` to `5150`, Login paths
to `3000`, and `/console` (without stripping the prefix) to `8080`.
Public requests to Identity and Login are still rejected unless the proxy passes
`X-Forwarded-Proto: https` or `Forwarded: proto=https`; Identity also rejects
that header when the direct peer is outside `IDENTITY_TRUSTED_PROXY`. Do not
expose ports 5150, 3000, or 8080 directly to untrusted networks in this mode.

### Rotating the Compose workload tokens

The current Compose file mounts one workload-token file per workload. For a
no-downtime rotation, temporarily mount current and previous files into Identity
and list both under `internal.workloads.login.static_tokens` or
`internal.workloads.console.static_tokens`; mount only the new file into Login
or Console. Recreate the updated workload, verify `/health/ready`, then remove
the previous file from Identity. Identity re-reads configured static token files
for each authentication attempt, and Console re-reads its token file on each
`/console/config.json` request.

## Kubernetes with Helm

See [`helm/identity/README.md`](helm/identity/README.md) for prerequisites,
Secret creation, certificate names, issuer requirements, and installation.
The chart creates a narrowly scoped projected ServiceAccount token and does
not grant Login Kubernetes API permissions.

## Built-in client installation and rotation

During installation, Identity creates the administrator, built-in Login
client, initial client-secret generation, and runtime state in one database
transaction. The installation response contains no client secret. Login then
uses its workload credential to retrieve the built-in client ID and the current
secret generation.

Identity periodically locks rotation in PostgreSQL, creates a new generation
after 60 days, and retains the previous generation for 24 hours. A new
generation expires after 90 days. Every Login replica refreshes its in-memory snapshot. The token
endpoint accepts both generations during the overlap, so instances may update
independently without per-pod credentials, shared files, or rollout
coordination.

Login exposes `/health/live` and `/health/ready`. Before installation,
readiness remains true so the installer is reachable. After installation it
becomes false when Login cannot obtain usable runtime configuration or its
current OAuth credential is close to expiry.

## Observability

Identity can export traces, structured logs and key business/audit events over
OTLP/HTTP (protobuf) to a collector. Login can export its server-side spans and
key events over OTLP/HTTP JSON. Helm leaves both exporters disabled and keeps
Identity's JSON console logs enabled until collector endpoints are explicitly
configured. Set `identity.observability.otlp.enabled` and
`login.observability.otlp.enabled` with their endpoints (or the Compose variables)
to point both at the collector. Login still treats browser-provided `traceparent` as
untrusted and starts a new trace with a link; Identity trusts only verified
workload identity or configured gateway networks.

| Setting | Compose | Helm |
| --- | --- | --- |
| OTLP endpoint | `IDENTITY_OTLP_ENABLE`, `OTEL_EXPORTER_OTLP_ENDPOINT` read by `deploy/config/identity.compose.yaml` (add them to the `server` environment block) | `identity.observability.otlp.*` |
| Console output | `observability.console` through the mounted compose configuration | `identity.observability.console` (enabled in production by the default values) |
| Trace sampling | production default 10%, override `observability.sampling.trace_ratio` in the mounted configuration | `identity.observability.sampling.traceRatio` |
| Trace trust | `observability.trace_context.trusted_gateways`; workload-verified internal calls are trusted when `trust_verified_workload` is true | `identity.observability.traceContext.*` |
| PII pseudonymization | `observability.pii.hmac_key.environment` / `file` | `identity.observability.pii.existingSecret` + `key` (mounted as `IDENTITY_PII_HMAC_KEY`) |
| Self-metrics | internal listener `/internal/observability/metrics` | `identity.observability.selfMetrics.*` |
| Login OTLP | `IDENTITY_LOGIN_OTLP_ENABLE`, `OTEL_EXPORTER_OTLP_ENDPOINT` | `login.observability.otlp.*` |
| Login self-metrics | `IDENTITY_LOGIN_METRICS_ENABLE` → `/health/metrics` | `login.observability.selfMetrics.enabled` |

Deployment responsibilities:

- Configure `identity.observability.otlp.endpoint` (or the standard
  `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable) to point at a reachable
  collector. Export failures are counted on the self-metrics endpoint and never
  block requests.
- Route `identity.event.category = audit` log records to the audit store and
  the rest to diagnostic storage. Retention targets (7-day traces, 14-day
  diagnostics, 90-day business/audit records) are enforced by the storage
  backend, not by the application.
- Grant diagnostic and audit query permissions separately.
- Trace trust is configured independently from proxy/IP trust. Only add
  networks to `trusted_gateways` when that path clears externally supplied
  `traceparent`/`tracestate` headers or authenticates the caller as a verified
  service.
- The `[REDACTED]` fallback applies when the HMAC key is missing or cannot be
  read; authentication continues with redacted PII output.
- Login key events (`login.callback.result`, `token.exchange.observed`,
  `logout.local.result`, `login.runtime_configuration.changed`) are exported
  only when `IDENTITY_LOGIN_OTLP_ENABLE=true`; the pipeline is bounded and
  drops instead of blocking, with drops exported on `/health/metrics` when
  `IDENTITY_LOGIN_METRICS_ENABLE=true`.
- Keep at least one output enabled when `observability.enable` is true.
  Startup fails with `observability is enabled but neither the console nor OTLP
  export is configured` (`src/infrastructure/observability/mod.rs:50`). The
  console output defaults to off in production, so an OTLP endpoint must then be
  configured explicitly; an enabled OTLP exporter with no endpoint falls back to
  `http://127.0.0.1:4318`.
