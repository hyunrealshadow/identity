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

PostgreSQL via SeaORM, form templates via Tera.

## Run

```sh
# development (config/development.yaml)
cargo run

# conformance mode
APP_ENV=conformance cargo run
```

Environment overrides: `APP_ENV`, `PORT`, `HOST`, `DATABASE_URL`.

### Prerequisites

- Rust 1.85+
- PostgreSQL (running on default port)
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
