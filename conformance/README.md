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
| `CONFORMANCE_API_TOKEN` | Unset | Account API token for the hosted suite; supplied through GitHub Secrets |
| `CONFORMANCE_ALIAS` | Profile default | Unique alias shared by the plan and seeded callbacks |
| `CONFORMANCE_SUITE_URL` | Local suite origin | Seeded callback/logout origin inside identity |
| `IDENTITY_URL` | `https://localhost:5150` for browser, `https://identity:5150` for suite discovery | When set, supplies both origins; `--discovery-origin` overrides the suite origin independently |
| `PROFILE` | `basic` | Test profile to create (`basic`, `implicit`, `hybrid`, `config`, `formpost-basic`, `formpost-implicit`, `formpost-hybrid`, `third-party-init`, `rp-init-logout`, `session`, or `backchannel`) |
| `CONFIG_PATH` | `conformance/plans/<profile>.json` | Config file path |
| `PLAN_NAME` | Derived from `PROFILE` | Conformance suite plan name |
| `TIMEOUT` | `60` | Timeout per test (seconds) |

## CI Integration

### GitHub Actions through Cloudflare Quick Tunnel

The `OIDC conformance through Cloudflare Tunnel` workflow is manually triggered
and connects to the **hosted** suite at https://www.certification.openid.net.
It starts only PostgreSQL, identity and a Cloudflare Quick Tunnel on the runner;
the suite itself and its database run on the official platform.

Before running it:

1. Sign in to the official platform with your Google or GitLab account.
2. Create an API token in the platform's token management page.
3. Add the token as the GitHub repository Actions secret `CONFORMANCE_API_TOKEN`.
   Use a normal account API token with permission to create/run plans, not a
   read-only plan sharing token. Do not put it in workflow inputs or commit it.
4. Under **Actions**, select the workflow and click **Run workflow**.

The workflow validates the token before building the environment. Plans are
created by the API under the token owner's account, so they appear on the official
platform. No plan IDs need to be entered manually. Each plan receives an alias
containing the repository ID, run ID, retry number and profile to avoid collisions
with other accounts, plans and runs. Seeded client callback and logout URLs use
that alias and the official suite origin. Hosted API HTTPS certificates are verified.

Every configured OP plan runs: Basic, Implicit, Hybrid, Config, three Form Post
plans, Third Party Initiated Login, RP Initiated Logout, Session Management and
Backchannel Logout (11 plans). Jobs run one at a time to limit load on the hosted
service, and a failed plan does not cancel the remaining jobs. Each has its own
runner, database, keys, browser sessions, tunnel and report. The final summary
includes every plan, including incomplete or missing reports. The hosted platform
controls the suite version; the workflow no longer builds or pins its source.

Cloudflare supplies a temporary `https://<random>.trycloudflare.com` hostname.
No personal domain, Cloudflare account or tunnel token is needed. The workflow
allocates the hostname first, then starts identity with that origin as its issuer.
The suite uses the public origin for discovery, authorization and token requests.
The connector forwards to `https://identity:5150` on the Compose network and
allows the generated origin certificate; the public HTTPS certificate is verified.
The disposable conformance environment automatically signs in the seeded test
user and approves consent without a separate login application.

Job summaries and `plan-url.txt` artifacts link to the official plan. Plans remain
on the official platform after the runner removes its environment. The temporary
issuer stops serving when cleanup closes the tunnel, so those plans cannot be
rerun against that issuer after the job ends. Quick Tunnels have no uptime guarantee.

The Foundation's [FAPI RP guidance](https://www.openid.net/certification/fapi-rp-conformance-testing-certification-submission-overview-for-open-banking-brazil/)
asks that the hosted platform not be used for automated build testing. This
workflow is manually dispatched for deliberate hosted test runs, not triggered
by pushes, pull requests or a schedule. Consult the Foundation about acceptable
usage if you plan frequent automated runs. Local development testing remains
available through `run.py` and `docker-compose.yml`.

Failures, timeouts, unfinished modules, empty plans, and incomplete plans fail the
job. `WARNING`, `SKIPPED`, and completed `REVIEW` results are retained in the
summary and do not fail the job; `REVIEW` still requires human assessment before
certification. Artifacts include the plan, per-module official logs, runner output,
service logs, and the hosted plan URL. Cleanup runs even when tests fail.

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
