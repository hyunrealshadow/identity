# Conformance Test Runner

Runs the [OpenID Foundation Conformance Test Suite](https://openid.net/certification/) against
the identity server locally using Docker Compose.

## Prerequisites

- Docker + Docker Compose
- `uv`
- The identity server built (`cargo build --release`)

## Quick Start

```bash
cd conformance
uv sync
uv run playwright install chromium
uv run python run.py
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
uv run python run.py                           # Start Docker, run all tests
uv run python run.py --profile implicit        # Run the Implicit OP certification plan
uv run python run.py --profile hybrid          # Run the Hybrid OP certification plan
uv run python run.py --profile third-party-init # Run the 3rd Party-Init OP plan
uv run python run.py --no-docker               # Services already running
uv run python run.py --plan-id <ID>            # Run on existing plan
uv run python run.py --config plans/basic.json # Override plan config JSON
uv run python run.py --timeout 30              # 30s timeout per test
uv run python run.py --exit-on-failure         # Exit 1 on failures
uv run python run.py --no-docker --results-dir results # Save official module logs and summary
```

### Check Plan Status

```bash
uv run python check_status.py <plan-id>
uv run python check_status.py <plan-id> --logs  # Show failure logs
```

### Run Single Test

```bash
uv run python run_single.py --plan-id <ID> --test oidcc-server
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SUITE_URL` | `https://localhost.emobix.co.uk:8443` | Conformance Suite URL |
| `IDENTITY_URL` | `https://localhost:5150` for browser, `https://identity:5150` for suite discovery | When set, supplies both origins; `--discovery-origin` overrides the suite origin independently |
| `LOGIN_URL` | `https://localhost:3443` | TLS-proxied TanStack Start login application URL |
| `PROFILE` | `basic` | Test profile to create (`basic`, `implicit`, `hybrid`, `config`, `formpost-basic`, `formpost-implicit`, `formpost-hybrid`, `third-party-init`, `rp-init-logout`, `session`, or `backchannel`) |
| `CONFIG_PATH` | `conformance/plans/<profile>.json` | Config file path |
| `PLAN_NAME` | Derived from `PROFILE` | Conformance suite plan name |
| `TIMEOUT` | `60` | Timeout per test (seconds) |

## CI Integration

### GitHub Actions through Cloudflare Zero Trust

The `OIDC conformance through Cloudflare Tunnel` workflow starts the isolated
Compose stack on a GitHub-hosted runner and connects a dedicated, remotely managed
[Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/get-started/).
Only the connector runs during the job; cleanup stops it and removes the test
database. The named tunnel and DNS records remain configured for subsequent runs.

Configure the following repository settings under **Settings → Secrets and
variables → Actions**:

| Setting | Kind | Example |
|---------|------|---------|
| `CLOUDFLARE_TUNNEL_TOKEN` | Secret | Token for a dedicated conformance tunnel |
| `CONFORMANCE_IDENTITY_URL` | Variable | `https://oidc-ci.example.com` |
| `CONFORMANCE_LOGIN_URL` | Variable | `https://login-ci.example.com` |

Use HTTPS origins without trailing slashes. In Cloudflare Zero Trust, create a
Cloudflared tunnel and configure these published application routes:

| Public hostname | Origin service | Origin setting |
|-----------------|----------------|----------------|
| `oidc-ci.example.com` | `https://identity:5150` | Enable **No TLS Verify** for the generated test certificate |
| `login-ci.example.com` | `http://login:3000` | Cloudflare supplies `X-Forwarded-Proto: https` |

The connector joins the same Docker network as these services. Do not connect
another runner or permanent connector to this dedicated tunnel. These test
hostnames must be reachable without a Cloudflare Access login challenge, service
token requirement, or interactive bot challenge: the official suite needs to
make ordinary OIDC requests. This exposes the disposable `APP_ENV=conformance`
instance, including its test-only auto-login and key-rotation endpoints.

Under **Actions**, select the workflow, choose an OP profile, and click **Run
workflow**. `suite_ref` selects a branch, tag, or full SHA from the official
[`openid/conformance-suite`](https://gitlab.com/openid/conformance-suite) source.
The workflow resolves it to an exact commit before building and records the SHA
with the artifacts. The existing Python harness creates and drives the official
suite's test modules via its API, including browser login and screenshot evidence;
protocol assertions are performed by the official Java suite.

The official suite and MongoDB remain local to the runner. The suite uses its
existing `https://localhost.emobix.co.uk:8443` callback URLs, which work inside
Compose and in the runner's browser; discovery, issuer, and authorization requests
use the public identity hostname through Cloudflare. This workflow runs the
official suite locally, rather than submitting a plan to the hosted
`www.certification.openid.net` service.

Failures, timeouts, unfinished modules, empty plans, and incomplete plans fail the
job. `WARNING`, `SKIPPED`, and completed `REVIEW` results are retained in the
summary and do not fail the job; `REVIEW` still requires human assessment before
certification. Artifacts include the plan, per-module official logs, runner output,
service logs, and suite revision. Cleanup runs even when tests fail.

### Local CI command

```yaml
- name: Run OIDC Conformance Tests
  run: |
    cd conformance
    uv sync
    uv run playwright install chromium
    uv run python run.py --exit-on-failure
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
