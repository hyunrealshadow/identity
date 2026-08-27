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

The workload credential and the OAuth client secret have separate lifecycles.
Rotating the workload credential changes who may call the internal API;
Identity's scheduled rotation changes the OAuth credential returned by that
API. The latter does not require a rollout.

## Docker Compose

The Compose deployment runs PostgreSQL, Identity, and Login. The internal
Identity listener (`5151`) and health listener (`8081`) are not published on
the host.

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

The default Identity URL is `https://identity.localhost:5150`. The certificate
must contain `identity.localhost` and `identity` as DNS SANs. Modern browsers
resolve the reserved `.localhost` suffix to loopback, while Compose resolves
the same name through the service network alias. If a real DNS name is used,
it must resolve from both the browser and the Login container.

All Login replicas must receive the same session secret. Scaling Login does
not create per-instance OAuth secrets:

```sh
docker compose --env-file deploy/.env -f deploy/docker-compose.yml up -d --scale login=3
```

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

Login exposes `/health/live` and `/health/ready`. Readiness becomes false when
it cannot obtain usable runtime configuration or its current OAuth credential
is close to expiry.
