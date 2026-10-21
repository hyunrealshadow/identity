# Identity

[![OIDC conformance test](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.github.com%2Frepos%2Fhyunrealshadow%2Fidentity%2Factions%2Fworkflows%2Foidc-conformance.yml%2Fruns%3Fbranch%3Dmain%26per_page%3D1&query=%24.workflow_runs%5B0%5D%5B%27status%27%2C%27conclusion%27%5D.%40string%28%29&label=OIDC%20conformance%20test&logo=github&color=blue)](https://github.com/hyunrealshadow/identity/actions/workflows/oidc-conformance.yml?query=branch%3Amain)

[Latest conformance summary](conformance/SUMMARY.md)

Identity is a self-hosted OAuth 2.0 authorization server and OpenID Connect
Provider built with Rust, Salvo, and PostgreSQL. Its companion Login application,
built with React and TanStack Start, provides installation, sign-in, consent,
device verification, and account management.

[Features](#features) · [Quick start](#quick-start) ·
[Configuration and deployment](#configuration-and-deployment) ·
[Development](#development) · [Documentation](#documentation)

## Features

### Authentication and accounts

| Area | Capabilities |
| --- | --- |
| Sign-in | Username or email identification, password authentication, Passkey/WebAuthn, and account selection across multiple signed-in accounts |
| Multi-factor authentication | TOTP authenticator apps, user-verified Passkeys, single-use recovery codes, and account-wide Passkey/OTP preference |
| Account management | Profile, username, email, password, language, and theme settings |
| Credential management | TOTP enrollment and removal, named Passkey enrollment and removal, and recovery-code regeneration |
| Sessions | Device and activity details, individual session revocation, and revocation of all other sessions |
| User interface | English and Simplified Chinese, browser language detection, and light/dark/system themes |

User-verified Passkeys satisfy `aal2` directly. Users can choose their preferred
MFA method; the password path still enforces the account's configured MFA.
Credential changes require recent authentication, with AAL2 required when MFA
is already enrolled.

Password, OTP, recovery-code, and consent forms work without JavaScript.
Passkeys require JavaScript and a secure browser context. See the
[Login guide](apps/login/README.md#passkeys) for enrollment and origin requirements.

### OAuth and OpenID Connect

| Area | Capabilities |
| --- | --- |
| Grants and flows | Authorization code, refresh token, client credentials, device authorization; OIDC code, implicit, and hybrid flows |
| Authorization | PKCE S256, nonce, consent, account selection, silent requests, reauthentication, `max_age`, `acr_values`, and claims requests |
| Discovery | OIDC discovery, OAuth server metadata, and public JWKS |
| Tokens and claims | Signed JWT access tokens and ID Tokens, encrypted ID Tokens, JSON/signed/encrypted UserInfo, and public/pairwise subjects |
| Token lifecycle | Refresh rotation and replay handling, revocation, and authenticated introspection |
| Request handling | Pushed Authorization Requests (PAR), signed/unsigned/encrypted Request Objects, and query/fragment/Form Post response modes |
| API authorization | Resource indicators, multiple audiences, resource-specific scopes, custom scope definitions, and per-client CORS |
| Client management | Dynamic registration and registration management; secret-based, JWT-based, and permitted public-client authentication |
| Logout | RP-initiated, front-channel, and back-channel logout; OP session iframe |

The runtime OAuth policy defaults to `"2.0"`; `"2.1"` selects stricter
authorization-code PKCE rules, with optional per-client overrides. Dynamic
registration is disabled by default. Available algorithms depend on active keys,
client metadata, and build features.

See the [protocol reference](docs/protocol.md) for endpoints, client policies,
resource and scope setup, and implementation limits.

### Operations

Identity includes ordered database migrations, runtime settings refresh,
automatic rotation of the built-in Login OAuth credential, health/readiness
checks, structured logs, optional OTLP export, and security audit records.

## Quick start

### Prerequisites

- Rust **1.99.0**, pinned in [rust-toolchain.toml](rust-toolchain.toml).
- PostgreSQL with an existing database and a user allowed to run migrations.
- Node.js **22** and pnpm **12.9.1**, as used by the deployment build.
- OpenSSL and native build tools; Linux builds use `pkg-config` and `libssl-dev`.

Run both terminals from the repository root. These examples use a POSIX shell;
in PowerShell, use `$env:NAME = "value"` for environment variables.

### 1. Start Identity

Set your database connection and generate a workload token. Keep the token value
available for the Login terminal.

```sh
export DATABASE_URL='postgres://identity:replace-with-password@localhost:5432/identity'
export IDENTITY_WORKLOAD_TOKEN="$(openssl rand -base64 32)"

cargo run --locked --bin identity
```

The default [development configuration](config/development.yaml) applies
database migrations automatically and generates a local TLS certificate.

| Service | Development URL |
| --- | --- |
| Public Identity API | `https://localhost:5150` |
| GraphQL | `https://localhost:5150/graphql` |
| Database health check | `https://localhost:5150/health` |
| Internal workload API | `https://localhost:5151` |

### 2. Start Login

In a second terminal, paste the **same workload token** used by Identity and
generate a separate cookie sealing secret:

```sh
export IDENTITY_WORKLOAD_TOKEN='paste-the-token-from-terminal-1'
export IDENTITY_LOGIN_SESSION_SECRET="$(openssl rand -base64 32)"
export IDENTITY_PUBLIC_APP_URL='https://localhost:3000'

pnpm install --frozen-lockfile
pnpm dev:login
```

Login runs at `https://localhost:3000`. Accept the local development certificate
in your browser. The development Login server accepts Identity's self-signed
certificate; production uses normal TLS certificate validation.

### 3. Complete installation

Open `https://localhost:3000` and enter the initial administrator's username,
email, and password, then select the signing-key algorithm. For the default
setup, use:

| Setting | Value |
| --- | --- |
| Identity URL / issuer | `https://localhost:5150` |
| Login application URL | `https://localhost:3000` |

Installation creates the administrator, signing material, built-in Login client,
and runtime settings. A complete `install` section in the service configuration
can also initialize an uninstalled database.

Initial passwords and password changes require 12–1024 characters and must pass
local policy and breached-password checks. Allow HTTPS access to Pwned Passwords
or configure a compatible range service; an unavailable checker rejects the
operation. See [password security](docs/security.md#password-policy).

## Configuration and deployment

### Configuration model

Identity loads `config/{environment}.yaml`. `APP_ENV` selects the environment,
with `RUST_ENV` as a fallback and `development` as the default. YAML templates
read process environment variables through `get_env`; the Rust service does
not automatically load a root `.env` file. Variables such as `PORT` and `HOST`
only apply where the selected template uses them.

| Configuration | Where it lives |
| --- | --- |
| Listeners, TLS, database, workload authentication, GraphQL limits, observability | Startup YAML |
| Issuer (`app.domain`), Login origin (`app.login_domain`), client metadata, password hashing, OAuth policies | PostgreSQL runtime settings and records |
| Runtime settings refresh | `settings.refresh_interval_secs` in YAML; 30 seconds by default |
| Login, consent, and device UI URLs | Derived from the installed Login origin |

### Login environment

| Variable | Purpose |
| --- | --- |
| `IDENTITY_API_URL` | Browser-visible Identity URL; defaults to `https://localhost:5150` |
| `IDENTITY_BACKCHANNEL_API_URL` | Server-side protocol and interactive API calls |
| `IDENTITY_BACKCHANNEL_GRAPHQL_URL` | Server-side GraphQL calls |
| `IDENTITY_INTERNAL_API_URL` | Internal workload API; defaults to `https://localhost:5151` |
| `IDENTITY_WORKLOAD_TOKEN_FILE` / `IDENTITY_WORKLOAD_TOKEN` | Workload credential file or inline development token |
| `IDENTITY_LOGIN_SESSION_SECRET` | Cookie sealing secret shared across Login replicas |
| `IDENTITY_PUBLIC_APP_URL` | Public HTTPS origin of Login |

Identity automatically rotates the built-in Login OAuth credential. Configure
the workload credential and a shared cookie sealing secret separately.

### Deployment options

- **Docker Compose:** [single-host deployment and upstream TLS](deploy/README.md).
- **Kubernetes:** [Helm chart](deploy/helm/identity/README.md), with optional
  [Gateway API examples](deploy/kubernetes/README.md).
- **Login server:** [production transport and environment](apps/login/README.md#production-transport).

Public URLs must use HTTPS. Identity can terminate TLS directly or trust a
configured upstream proxy. Keep the internal listener private; it authenticates
Login using static workload tokens or Kubernetes projected ServiceAccount tokens.

Private HTTP backchannel/internal calls require explicit Login opt-ins and the
corresponding Identity network trust configuration. The production Login server
uses HTTP behind an HTTPS proxy by default, or can terminate TLS with
`NITRO_SSL_CERT_FILE` and `NITRO_SSL_KEY_FILE`. Follow the deployment guide for
the complete configuration.

## Development

### Repository layout

```text
src/
  domain/          Domain models, protocol types, and repository contracts
  application/     Authentication, account, and OAuth/OIDC use cases
  infrastructure/  SeaORM persistence, cryptography, settings, and observability
  web/             Salvo routes, middleware, GraphQL, and protocol HTML
  boot/            Configuration, application assembly, and listener startup
migration/         Ordered schema and data migrations
apps/login/        React/TanStack Start UI and server-side API integration
assets/            Fluent translations, Tera templates, and error-page styles
config/            Development, test, and conformance startup configuration
conformance/       OIDC conformance runner and test plans
deploy/            Docker Compose, container builds, and Helm chart
docs/              Protocol and security references
```

Domain and application code use repository contracts; infrastructure supplies
persistence adapters. Login owns the interactive UI. Identity renders
protocol-required HTML, including Form Post, session checks, front-channel
logout, and terminal error pages.

### Build and checks

```sh
cargo build --locked --release --bin identity
pnpm build:error-css
pnpm build:login

cargo test --workspace --locked
cargo check --workspace --all-targets --features oidc-conformance --locked
cargo fmt --all -- --check
pnpm --filter login test
```

Run `pnpm install --frozen-lockfile` before the frontend commands. Production
Login startup and TLS configuration are covered in the
[Login guide](apps/login/README.md#production-transport).

Database schema changes are managed by the `migration` crate. To apply migrations
separately, set `DATABASE_URL` and run:

```sh
cargo run --locked -p migration --bin identity-migration -- up
```

### OIDC conformance

The [conformance harness](conformance/README.md) runs profile-based tests with
Docker Compose, `uv`, and Playwright. Its isolated image enables
`oidc-conformance` and `allow-none-alg`; use the default build for deployments.

Conformance results depend on the profile, features, client configuration, and
deployment. Review warnings, skips, and manual-review results. The runner and CI
badge do not establish OpenID certification.

After each CI run, [conformance/SUMMARY.md](conformance/SUMMARY.md) is updated
with all plan results, the tested commit, and a link to that exact CI run and
attempt. The same Markdown is available in the run summary and as an artifact.

## Documentation

| Guide | Contents |
| --- | --- |
| [Protocol reference](docs/protocol.md) | HTTP endpoints, client policies, resource indicators, scopes, PAR, and limits |
| [Login application](apps/login/README.md) | UI behavior, Passkeys, environment, production transport, and health |
| [Deployment](deploy/README.md) | Compose, workload credentials, TLS, and observability configuration |
| [Helm chart](deploy/helm/identity/README.md) | Replicated Kubernetes deployment |
| [Security](docs/security.md) | Password requirements, MFA, session protection, and security auditing |
| [Observability](deploy/README.md#observability) | OTLP pipelines, PII handling, queues, and export configuration |
| [Conformance](conformance/README.md) | Profiles, local/hosted runners, options, and result interpretation |

## License

Copyright 2026 UnrealShadow. Licensed under the [Apache License, Version 2.0](LICENSE).
