# Conformance Test Runner

Runs the [OpenID Foundation Conformance Test Suite](https://openid.net/certification/) against
the identity server locally using Docker Compose.

## Prerequisites

- Docker + Docker Compose
- `uv`
- Docker builds the identity server with the conformance feature automatically

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
| `PROFILE` | `basic` | Test profile to create (`basic`, `implicit`, `hybrid`, `config`, `formpost-basic`, `formpost-implicit`, `formpost-hybrid`, `third-party-init`, `rp-init-logout`, `session`, or `backchannel`) |
| `CONFIG_PATH` | `conformance/plans/<profile>.json` | Config file path |
| `PLAN_NAME` | Derived from `PROFILE` | Conformance suite plan name |
| `TIMEOUT` | `60` | Timeout per test (seconds) |

## CI Integration

### GitHub Actions through Cloudflare Quick Tunnel

The `OIDC conformance through Cloudflare Tunnel` workflow starts the isolated
Compose stack on a GitHub-hosted runner and allocates a
[Cloudflare Quick Tunnel](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/).
Cloudflare supplies a temporary `https://<random>.trycloudflare.com` hostname;
no personal domain, Cloudflare account, tunnel token, or repository URL variable
is required. Existing `CLOUDFLARE_TUNNEL_TOKEN` and `CONFORMANCE_IDENTITY_URL`
settings are no longer used by the workflow.

The job builds the images, starts only the tunnel connector, reads its allocated
URL, and then starts identity with that exact public origin as its issuer. The
suite uses the same origin for discovery and browser authorization. The generated
URL is recorded in the job summary and `tunnel-url.txt` artifact. Cleanup stops
the tunnel and removes the test database; the hostname stops serving the runner.
Each new run gets a new hostname. Quick Tunnels have no uptime guarantee, so a
Cloudflare outage can fail a CI run independently of protocol conformance.

The connector joins the same Docker network as identity and forwards to
`https://identity:5150`. Origin certificate verification is disabled for the
generated test certificate; the public HTTPS endpoint is still verified by
the readiness probe. The tunnel is public, with no interactive email or Access
challenge, so the official suite can make ordinary OIDC requests. This exposes
the disposable `APP_ENV=conformance`
instance, including its test-only auto-login, auto-consent and key-rotation endpoints.
The login application is not built or started. Authorization interactions go
directly to identity's `/conformance/auto-login` and `/conformance/auto-consent`
auto-submit forms, which authenticate the test user and approve consent through
the normal application services. Browser cookies and OIDC callbacks are retained.

Under **Actions**, select the workflow and click **Run workflow**. Every supported
OP plan from `plans.py` runs automatically: Basic, Implicit, Hybrid, Config,
the three Form Post plans, Third Party Initiated Login, RP Initiated Logout,
Session Management, and Backchannel Logout (11 plans). Each plan has its own
runner, database, keys, browser sessions, Quick Tunnel, and report. Up to three
plans run concurrently; a failure or manual review in one plan does not cancel
the others. The workflow succeeds only when every plan job succeeds. A final
summary job collects the per-plan reports into one table, including missing or
incomplete reports. Artifacts are named separately for each profile.

`suite_ref` selects a branch, tag, or full SHA from the official
[`openid/conformance-suite`](https://gitlab.com/openid/conformance-suite) source.
The workflow resolves it once to an exact commit shared by all plans and records the SHA
with the artifacts. The existing Python harness creates and drives the official
suite's test modules via its API, including automated browser login and consent;
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

This automated environment has no real login UI. It does not upload screenshots
of auto-submit forms or callbacks as proof of a user-facing login prompt. If the
official suite requests such evidence, the harness records
`MANUAL_REVIEW_REQUIRED`, leaves that official test incomplete, and stops the plan
to avoid conflicts with its active callback alias. The CI job fails rather than
reporting an incomplete plan as passed; complete UI evidence separately for
certification. Other completed `REVIEW` results remain visible in the summary.

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

- The auto-login and auto-consent routes are **only mounted when `APP_ENV=conformance`** with the `oidc-conformance` feature.
- Test credentials are scoped to the `identity_conformance` database only.
- The route does not exist in development or production environments.

## Architecture

```
scripts/
  client.py      # Conformance Suite API client
  browser_auth.py # Browser follows automatic login and consent redirects
  runner.py      # Test execution engine
run.py           # Main CI entry point
```
