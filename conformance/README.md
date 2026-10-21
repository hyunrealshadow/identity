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
| `ci_summary.py` | Generate the standalone CI Markdown report from plan artifacts |
| `ci_commit_summary.py` | Publish that report to the tested branch without changing other files |

## Usage

### Run Full Suite

```bash
uv run python run.py                           # Start Docker, run all tests
uv run python run.py --profile implicit        # Run the Implicit OP certification plan
uv run python run.py --profile hybrid          # Run the Hybrid OP certification plan
uv run python run.py --profile dynamic         # Run Dynamic OP with suite-registered clients
uv run python run.py --profile frontchannel    # Run the Front-Channel Logout OP plan
uv run python run.py --profile dynamic --response-type "code id_token"
uv run python run.py --profile frontchannel --response-type "id_token token"
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
| `LOGIN_URL` | `https://localhost:3000` | Standard Login application origin; CI allocates a separate Quick Tunnel |
| `IDENTITY_URL` | `https://localhost:5150` for browser, `https://identity:5150` for suite discovery | When set, supplies both origins; `--discovery-origin` overrides the suite origin independently |
| `PROFILE` | `basic` | Test profile to create (`basic`, `implicit`, `hybrid`, `config`, `formpost-basic`, `formpost-implicit`, `formpost-hybrid`, `third-party-init`, `rp-init-logout`, `session`, `backchannel`, `dynamic`, or `frontchannel`) |
| `CONFIG_PATH` | `conformance/plans/<profile>.json` | Config file path |
| `PLAN_NAME` | Derived from `PROFILE` | Conformance suite plan name |
| `TIMEOUT` | `60` | Timeout per test (seconds) |

## CI Integration

### GitHub Actions through Cloudflare Quick Tunnel

The `OIDC conformance test` workflow is manually triggered
and connects to the **hosted** suite at https://www.certification.openid.net.
It starts PostgreSQL, identity, the standard Login application and two Quick Tunnels on the runner;
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
plans, Third Party Initiated Login, RP Initiated Logout, Session Management,
Backchannel Logout, Dynamic OP and Front-Channel Logout (13 profiles). Dynamic,
Third Party Initiated Login, RP Initiated Logout, Session Management, Backchannel
and Front-Channel expand across all six supported response types, for 43 plan runs.
Jobs run one at a time to limit load on the hosted
service, and a failed plan does not cancel the remaining jobs. Each has its own
runner, database, keys, browser sessions, tunnels and report. A preparation job
validates the API token and builds the identity, Login and Python test runner images once,
then shares them as a short-lived workflow artifact. The runner image includes the locked
Python dependencies, Chromium and its system libraries; preparation checks its tests and
launches a real browser before upload. Each plan loads those same images without rebuilding
or installing uv, Python packages, browsers or OS packages. Readiness and the plan run in
fresh runner containers, with reports mounted into the job's evidence directory.
Browser interaction failures stop the plan with `BROWSER_INTERACTION_FAILED` and save
the current URL, error, page text, screenshot and Playwright trace under `results/browser/`.
These diagnostics are separate from the screenshots submitted for certification review.
No container registry credentials are needed. The final summary
includes every plan, including incomplete or missing reports. The hosted platform
controls the suite version; the workflow no longer builds or pins its source.
The UI review column counts official `REVIEW` results as well as missing browser evidence.

Dynamic OP, Third Party Initiated Login and all four logout/session profiles each
run `code`, `id_token`, `id_token token`,
`code id_token`, `code token`, and `code id_token token`. Job names, suite aliases,
artifact names and summary rows identify both the profile and response type so
their reports cannot overwrite one another. For local runs, select one with
`--response-type`; omitting it defaults to `code`. Basic, Implicit and Hybrid
(and their Form Post plans) expand the applicable response types inside the
official plan, so they do not need additional CI jobs. Config checks discovery
metadata without a response-type variant. RP Initiated Logout and Session
Management use a separate all-response-types test client; Third Party Initiated
Login dynamically registers its own clients with `initiate_login_uri`.
The Basic clients retain their code-only permissions.

Cloudflare supplies separate temporary `https://<random>.trycloudflare.com` hostnames for identity and Login.
No personal domain, Cloudflare account or tunnel token is needed. The workflow
allocates both hostnames first, then installs identity with its public issuer and the Login origin.
The suite uses the public origin for discovery, authorization and token requests.
The connector forwards to `https://identity:5150` on the Compose network and
allows the generated origin certificate; the public HTTPS certificate is verified.
Python Playwright fills the standard identifier and password forms, selects
accounts and approves consent through the Login application's regular routes.
Login uses the standard authenticated internal API, session and CSRF transports.
The generated identity TLS material is shared read-only with Login for this
disposable environment; Login trusts that certificate for its private API calls.

After each plan run, CI publishes everything through the official suite API,
including failed or interrupted plans when a plan ID was saved. The publication
step uses the same runner image and mounted results directory as the test run so
container-owned evidence files can be updated without host permission errors. Publication errors
fail the job; no plan is published if creation never completed. This makes test
configuration, keys, secrets and logs public, so this workflow uses only disposable
environments and dedicated test credentials. Publication does not request certification.
Job summaries and `plan-url.txt` artifacts link to the public official plan after
successful publication. Plans remain
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

### Standalone Markdown summary

After all plan jobs finish, CI generates [SUMMARY.md](SUMMARY.md), displays the
same report in the Actions run summary, and uploads it as
`oidc-conformance-summary-<run_id>-<attempt>` (retained for 14 days). The report
contains the tested commit, branch, exact CI run/attempt link, per-plan status and
counts, and official plan links. Failed preparation and missing or incomplete
reports remain visible.

CI commits only `conformance/SUMMARY.md` to the branch on which the workflow was
dispatched, preserving changes made to that branch while tests were running.
The summary job has `contents: write`; repository rules must allow its bot commit.
Publication never forces a push or bypasses branch protection. If it is rejected,
the report remains available in the run summary and downloadable artifact.
Tag runs produce the report and artifact without updating a branch.

Each plan's evidence artifact includes the run ID and attempt number. Re-running
failed jobs uses the newest available attempt for each plan while retaining
evidence from successful jobs that were not rerun. Re-running an older workflow
cannot replace a report published by a newer run.

### Browser evidence

Login evidence is captured from the actual visible identifier/password page,
before submitting credentials in the same browser interaction. Callback pages
and separately replayed requests are never uploaded as login prompt evidence.
Redirect URI error evidence is captured only from an actual OP error response
in that interaction. The suite's evidence source selects the screenshot type;
login and error-page screenshots cannot substitute for each other.
Dynamic registration's Logo, privacy-policy and terms-of-service checks use the
actual login page, which displays the requesting client's registered public metadata.
If the suite asks for UI evidence that was not observed, the harness records
`MANUAL_REVIEW_REQUIRED` and stops the plan. Completed `REVIEW` results still
require human assessment for certification.

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
environment uses `config/conformance.yaml` with two fixed test accounts:

| Username | Email | Password |
| --- | --- | --- |
| `conformance-test` | `conformance-test@example.com` | `ConformanceTest1!` |
| `conformance-test-2` | `conformance-test-2@example.com` | `ConformanceTest2!` |

Each protocol profile also has two ordinary Basic-authenticated clients and a
separate `client_secret_post` client. `client2` must not reuse the POST-only
client: the refresh-token module authenticates its second client using Basic.
The Backchannel Logout plan uses a separate client (`00000010-0000-0000-0000-000000000001`)
with only a backchannel notification URI. Front-Channel Logout uses its own client
(`00000011-0000-0000-0000-000000000001`) with only a frontchannel notification URI.
Dynamic OP lets the suite register its own clients instead of using seed credentials.
Ordinary clients used by RP-Initiated
Logout and Session Management do not register notification endpoints those plans
do not serve. Initialization also corrects these fields in existing test databases.

Both accounts have stable, distinct user and credential OIDs. Initialization is
idempotent and adds the second account to an existing single-account database.
The browser honors recognized login hints and uses the other account when an
account-selection prompt is requested. Sessions persist within a test module and
are reset between modules. Seeded clients use the standard consent flow.
`LOGIN_URL` must be set before first installation if using a custom Login origin.

## Security Notes

- There are no auto-login or auto-consent endpoints; authentication and consent use the standard application.
- Test credentials are scoped to the `identity_conformance` database only.
- Only the key-rotation helper is mounted with `APP_ENV=conformance` and the `oidc-conformance` feature.
- Compose workload and cookie-sealing defaults are disposable test credentials only.

## Architecture

```
scripts/
  client.py      # Conformance Suite API client
  browser_auth.py # Browser submits standard Login and consent forms
  runner.py      # Test execution engine
run.py           # Main CI entry point
```
