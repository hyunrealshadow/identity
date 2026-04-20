# Conformance Test Runner

Runs the [OpenID Foundation Conformance Test Suite](https://openid.net/certification/) against
the identity server locally using Docker Compose.

## Prerequisites

- Docker + Docker Compose
- `curl` and `jq` installed locally (for `run-tests.sh`)
- The identity server built (`cargo build --release`)

## Quick Start

```bash
cd conformance
./run-tests.sh
```

Exits 0 if no tests FAILED, exits 1 if any FAILED. WARNING results are printed
but do not affect the exit code.

## What It Does

1. Starts Postgres, identity (`APP_ENV=conformance`), and the Conformance Suite via Docker Compose
2. Waits for both services to be healthy
3. Creates a test plan using `conformance-config.json`
4. Runs all test modules automatically — login is handled by `POST /conformance/auto-login`
5. Reports PASSED / WARNING / FAILED per module
6. Tears down the stack and exits

## First-Time Setup: Seed Data

After migrations run automatically on startup, apply the seed data:

```bash
# 1. Generate password hash for "ConformanceTest1!"
# (replace the hash values in the SQL before running)
#
# From the repo root:
cargo run --bin tool -- hash-password ConformanceTest1!
# Output looks like: $argon2id$v=19$m=65536,t=3,p=1$<SALT_BASE64>$<HASH>

# 2. Edit conformance/seed/conformance-seed.sql:
#    - Replace <PHC_HASH>    with the full "$argon2id$..." string
#    - Replace <SALT_BASE64> with the base64 salt (between last two "$" of PHC string)

# 3. Apply the seed (while the stack is running):
docker compose -f conformance/docker-compose.yml up -d db
psql postgres://identity:identity@localhost:5432/identity_conformance \
  -f conformance/seed/conformance-seed.sql
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SUITE_URL` | `https://localhost:8443` | Conformance Suite base URL |
| `IDENTITY_HEALTH` | `http://localhost:5150/health` | Identity health endpoint |
| `TIMEOUT` | `120` | Seconds to wait for services to become ready |

## CI Integration

```yaml
- name: Run OIDC Conformance Tests
  run: cd conformance && ./run-tests.sh
```

## Security Notes

- `POST /conformance/auto-login` is **only mounted when `APP_ENV=conformance`**. The route
  does not exist in development or production environments.
- `conformance.yaml` sets `dangerously_truncate: false` — safe to run repeatedly without
  losing seed data.
- Test credentials are scoped to the `identity_conformance` database only.
