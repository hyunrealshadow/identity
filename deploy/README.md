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
| Login authenticates to Identity | Shared static workload token file | Projected ServiceAccount JWT |
| Login cookie encryption | Shared `IDENTITY_LOGIN_SESSION_SECRET` | Shared Kubernetes Secret |
| Built-in OAuth client secret | PostgreSQL; fetched and refreshed in memory | PostgreSQL; fetched and refreshed in memory |
| Identity TLS | Compose secret files | Existing TLS Secret |
| Login TLS | Compose secret files | Optional existing TLS Secret or upstream proxy |

The workload credential and the OAuth client secret have separate lifecycles.
Rotating the workload credential changes who may call the internal API;
Identity's scheduled rotation changes the OAuth credential returned by that
API. The latter does not require a rollout.

## Docker Compose

The Compose deployment runs PostgreSQL, Identity, and Login. Identity uses four
separate listeners: public protocol API (`5150`), internal workload API
(`5151`), GraphQL (`5152`), and health (`8081`). Only the public listener is
published on the host. Login always reaches Identity through the private
Compose service name rather than the public DNS name.

1. Copy `deploy/.env.example` to `deploy/.env` and replace both secrets.
2. Create `deploy/secrets/login-workload-token` with at least 32 random
   characters, for example `openssl rand -base64 32`.
3. Place the Identity server certificate, private key, and issuing CA at
   `deploy/secrets/identity.crt`, `deploy/secrets/identity.key`, and
   `deploy/secrets/identity-ca.crt`.
4. Start the stack from the repository root:

   ```sh
   docker compose --env-file deploy/.env -f deploy/docker-compose.yml up --build -d
   ```

The default Identity and Login URLs are `https://identity.localhost:5150` and
`https://identity.localhost:3000`. Compose mounts the supplied certificate into
both production servers, so it must contain `identity.localhost` and `server`
as DNS SANs. Modern browsers resolve the reserved `.localhost` suffix to
loopback, while Compose resolves the same name through the service network
alias. If a real DNS name is used, it must resolve from both the browser and the
Login container.

All Login replicas must receive the same session secret. Scaling Login does
not create per-instance OAuth secrets:

```sh
docker compose --env-file deploy/.env -f deploy/docker-compose.yml up -d --scale login=3
```

### TLS terminated by an upstream proxy

To run both application containers over HTTP, add the upstream override:

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
listeners directly over HTTP. Do not use a public client address range. The
external `IDENTITY_PUBLIC_URL` and `LOGIN_PUBLIC_URL` must remain HTTPS URLs.

The override removes all application TLS certificate and CA mounts, switches
every Login-to-Identity call to the private HTTP service ports, and changes its
health check to HTTP.
Public requests to either application are still rejected unless the proxy
passes `X-Forwarded-Proto: https` or `Forwarded: proto=https`; Identity also
rejects that header when the direct peer is outside `IDENTITY_TRUSTED_PROXY`.
Do not expose ports 5150 or 3000 directly to untrusted networks in this mode.

### Rotating the Compose workload token

The current Compose file mounts one workload-token file. For a no-downtime
rotation, temporarily mount current and previous files into Identity and list
both under `internal.workloads.login.static_tokens`; mount only the new file
into Login. Recreate Login, verify `/health/ready`, then remove the previous
file from Identity. Identity re-reads configured static token files for each
authentication attempt.

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

Identity periodically locks rotation in PostgreSQL, creates a new generation,
and retains the previous generation for `retire_after_secs` (24 hours by
default). Every Login replica refreshes its in-memory snapshot. The token
endpoint accepts both generations during the overlap, so instances may update
independently without per-pod credentials, shared files, or rollout
coordination.

Login exposes `/health/live` and `/health/ready`. Before installation,
readiness remains true so the installer is reachable. After installation it
becomes false when Login cannot obtain usable runtime configuration or its
current OAuth credential is close to expiry.
