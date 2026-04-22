# Conformance Test Runner

Runs the [OpenID Foundation Conformance Test Suite](https://openid.net/certification/) against
the identity server locally using Docker Compose.

## Prerequisites

- Docker + Docker Compose
- Python 3.10+ with `requests` library
- The identity server built (`cargo build --release`)

## Quick Start

```bash
cd conformance
pip install requests
python run.py
```

Exits 0 if no tests fail (PASSED, WARNING, SKIPPED, REVIEW are acceptable).
Use `--exit-on-failure` to exit 1 on any non-passing results.

## Scripts

| Script | Description |
|--------|-------------|
| `run.py` | Main entry point - runs full test suite |
| `check_status.py` | Check status of an existing plan |
| `run_single.py` | Run a single test module |

## Usage

### Run Full Suite

```bash
python run.py                           # Start Docker, run all tests
python run.py --no-docker               # Services already running
python run.py --plan-id <ID>            # Run on existing plan
python run.py --timeout 30              # 30s timeout per test
python run.py --exit-on-failure         # Exit 1 on failures
```

### Check Plan Status

```bash
python check_status.py <plan-id>
python check_status.py <plan-id> --logs  # Show failure logs
```

### Run Single Test

```bash
python run_single.py --plan-id <ID> --test oidcc-server
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SUITE_URL` | `https://localhost.emobix.co.uk:8443` | Conformance Suite URL |
| `IDENTITY_URL` | `http://localhost:5150` | Identity server URL |
| `CONFIG_PATH` | `conformance/conformance-config.json` | Config file path |
| `TIMEOUT` | `60` | Timeout per test (seconds) |

## CI Integration

```yaml
- name: Run OIDC Conformance Tests
  run: |
    cd conformance
    pip install requests
    python run.py --exit-on-failure
```

## Seed Data

Seed data is applied automatically via database migrations. The conformance
environment uses `config/conformance.yaml` with pre-configured test users.

## Security Notes

- `POST /conformance/auto-login` is **only mounted when `APP_ENV=conformance`**.
- Test credentials are scoped to the `identity_conformance` database only.
- The route does not exist in development or production environments.

## Architecture

```
scripts/
  client.py      # Conformance Suite API client
  auto_login.py  # Automatic login handler
  runner.py      # Test execution engine
run.py           # Main CI entry point
```