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

The Rust protocol service must be available to the Start server at
`IDENTITY_API_URL` (default `https://localhost:5150`). Login and consent APIs
are proxied server-side; their successful responses send the browser directly
back to the OP continuation endpoint. The Rust JSON API uses
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
liveness and runtime-configuration readiness (secret within 30 minutes of
expiry reports unready) so proxies can stop routing traffic before a rotated
generation expires.

When using a custom local hostname, start Vite with `--host`, trust its
self-signed certificate, and configure the same HTTPS origin in Identity.

All state-changing interactions are native HTML form POSTs. Client JavaScript
intercepts the same forms only to provide enhanced navigation; disabling
JavaScript preserves the complete login and consent flow.
