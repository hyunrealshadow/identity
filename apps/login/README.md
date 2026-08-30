# Identity Login

TanStack Start application for interactive login and OAuth consent. The UI is
built with HeroUI v3 and Tailwind CSS v4.

## Development

```sh
pnpm dev
```

The Vite development server uses an automatically generated self-signed
certificate and is available at `https://localhost:3000`. Accept the
certificate warning in the browser the first time you open it. In development,
the Vite server also accepts the local Identity server's self-signed
certificate; production builds retain normal TLS certificate validation.

## Production transport

`pnpm build` uses the official Nitro Node server adapter and `pnpm start` runs
the generated production server. Production listens on HTTP by default and
requires the upstream proxy to report `X-Forwarded-Proto: https` or
`Forwarded: proto=https`; liveness and readiness probes are exempt. Set both
`NITRO_SSL_CERT_FILE` and `NITRO_SSL_KEY_FILE` to make the production process
terminate TLS itself. Providing only one file is a startup error.

Identity's browser-visible public URL is configured with `IDENTITY_API_URL`
(default `https://localhost:5150`) and must use HTTPS. It constructs browser
authorization redirects; it is not the default route for pod-to-pod or
container-to-container traffic.

Server-side Login, consent, token, and GraphQL calls use
`IDENTITY_BACKCHANNEL_API_URL` and `IDENTITY_BACKCHANNEL_GRAPHQL_URL`. Set both
to private Identity Service names. They remain HTTPS by default; a deliberate
private-network HTTP deployment must additionally set
`IDENTITY_BACKCHANNEL_ALLOW_HTTP=true`. Successful Login and consent responses
still send the browser directly to the public OP continuation endpoint. The
Rust JSON API uses
`X-Sessions` and `X-CSRF-Token`; API responses return updated values through
the `sessions` and `csrf_token` JSON fields. The Start server keeps the session
list in its own secure, HttpOnly first-party cookie and translates it to the API
header.

Installation and runtime configuration use the separate internal Identity
listener configured by `IDENTITY_INTERNAL_API_URL` (default
`https://localhost:5151`). Every internal call is authenticated with the Login
workload credential: the file from `IDENTITY_WORKLOAD_TOKEN_FILE` (or the
inline `IDENTITY_WORKLOAD_TOKEN` for development), which must match Identity's
`internal.workloads.login` configuration. Do not expose that listener through
the public ingress.

The internal API also remains HTTPS by default. A private-network HTTP
deployment must set `IDENTITY_INTERNAL_API_ALLOW_HTTP=true`; an HTTP URL without
that explicit opt-in is rejected.

Configure the Identity runtime settings to point to the development server:

- Login URL: `https://localhost:3000/login`
- Consent URL: `https://localhost:3000/consent`

The same application also hosts the account and session management UI at `/`.
Installation creates its confidential OIDC client automatically. Identity
returns the current OAuth client generation over the internal
runtime-configuration API; the BFF keeps the snapshot in memory only and
refreshes it on demand. No client credential file is written or persisted.

The cookie sealing key is static and deployer-provided:
`IDENTITY_LOGIN_SESSION_SECRET` (at least 32 random bytes) must be identical
across every replica — it only encrypts the session cookies, it is never
rotated. Production and Kubernetes deployments inject
`IDENTITY_INTERNAL_API_URL`, `IDENTITY_WORKLOAD_TOKEN_FILE` (projected
ServiceAccount token or a mounted static token),
`IDENTITY_LOGIN_SESSION_SECRET`, and `IDENTITY_PUBLIC_APP_URL`. These values
are server-only and are never included in browser JavaScript.

The health endpoints `/health/live` and `/health/ready` report process
liveness and application readiness. An uninstalled deployment is ready to
serve the installer; after installation, readiness requires usable runtime
configuration (a secret within 30 minutes of expiry reports unready) so proxies
can stop routing traffic before a rotated generation expires.

When using a custom local hostname, start Vite with `--host`, trust its
self-signed certificate, and configure the same HTTPS origin in Identity.

All state-changing interactions are native HTML form POSTs. Client JavaScript
intercepts the same forms only to provide enhanced navigation; disabling
JavaScript preserves the complete login and consent flow.
