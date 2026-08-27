# Identity

OpenID Connect Provider (OP) built with Rust — passes the OIDC conformance test suite.

## Architecture

Clean Architecture with dependency inversion:

```
src/
  domain/         — Entities, value objects, repository traits
  application/    — Use cases / services (no I/O)
  infrastructure/ — Repositories (SeaORM), crypto, templating
  web/            — HTTP handlers (Salvo), session management
  boot/           — App assembly, server startup
```

PostgreSQL via SeaORM. Interactive login, consent, and installation UI lives in
the external React/TanStack application. This service renders only terminal
error pages and protocol-required HTML documents (`form_post`, session iframe,
and front-channel logout).

The external UI locations are configured through the `app.login_url` and
`app.consent_url` runtime settings. They must be set before an interactive OIDC
flow can redirect to the React application.

The TanStack Start application is located in `apps/login`. It provides login,
consent, installation, and GraphQL-backed account/session management. Both Identity and
the public Login origin must be exposed through HTTPS. Configure the runtime
settings with HTTPS Login and Consent URLs, then start the application with:

```sh
pnpm install --frozen-lockfile
pnpm dev:login
```

The application proxies interactive JSON API requests to `IDENTITY_API_URL`,
which defaults to `https://127.0.0.1:5150`. Once login or consent has updated
the authorization interaction, the browser returns directly to the OP
`/oauth2/continue` endpoint. Login and consent use native POST forms without
JavaScript and are progressively enhanced after hydration.

Installation and Login runtime configuration are served on the separate
internal listener (port `5151` by default). Every internal endpoint requires
a workload credential: a static token from `internal.workloads.login` or a
Kubernetes projected ServiceAccount token. Configure Login with
`IDENTITY_INTERNAL_API_URL` and the matching workload credential, and keep
this listener off the public ingress.

Identity accepts only two TLS deployment modes under `server.tls.termination`:
`direct`, where Identity terminates TLS itself, and `upstream`, where a trusted
reverse proxy terminates TLS. Upstream mode requires
`server.tls.trusted_proxies` to list the proxy IP networks. Identity accepts
`Forwarded: proto=https` or `X-Forwarded-Proto: https` only when the TCP peer
belongs to one of those networks; the same boundary applies to
`X-Forwarded-For` and `X-Real-IP` when recording session audit data. Direct
clients cannot spoof these headers. In both modes, `server.host` must use
`https://`.

```yaml
server:
  tls:
    termination: upstream
    trusted_proxies:
      - 10.0.0.0/8
      - fd00::/8
```

## Run

```sh
# development (config/development.yaml)
cargo run

# conformance mode
APP_ENV=conformance cargo run

# rebuild the server-rendered error page stylesheet
pnpm install --frozen-lockfile
pnpm build:error-css
```

Environment overrides: `APP_ENV`, `PORT`, `HOST`, `DATABASE_URL`.

Deployment examples for persisting the built-in Login application's client ID
and secret are documented in `deploy/README.md`.

### Prerequisites

- Rust 1.85+
- PostgreSQL (running on default port)
- Node.js and pnpm (error-page CSS only)
- `sea-orm-cli` for migration management

### Database

```sh
# run migrations
cargo run --bin tool -- migrate

# seed test data
cargo run --bin tool -- seed
```

## Test

```sh
# unit + integration
cargo test --workspace

# OIDC conformance suite (requires Docker)
cd conformance
uv sync
uv run playwright install chromium
uv run python run.py --profile basic
```

Available profiles: `basic`, `implicit`, `hybrid`, `config`, `formpost-basic`, `formpost-implicit`, `formpost-hybrid`, `rp-init-logout`, `session`, `backchannel`.

## Features

- Authorization code, implicit, hybrid flows
- Form Post response mode
- PKCE, refresh tokens, ID tokens
- RP-initiated, front-channel, back-channel logout
- Session management (OP iframe)
- UserInfo endpoint
- Request objects (signed + unsigned)
- TOTP MFA
- Scope-based claims (profile, email, address, phone)
- Pairwise subject identifiers
- Client authentication: client_secret_basic, client_secret_post, client_secret_jwt, private_key_jwt
