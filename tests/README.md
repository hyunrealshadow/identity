# Rust Testing Boundaries

Keep only unit tests in `src/`. Place all integration tests in the repository-root `tests/` directory.

Using a mock repository does not make a test an integration test. An application service, parser, middleware, or algorithm tested in isolation with fake/mock dependencies is still a unit test. Tests that assemble real production routing, middleware, application services, and repository implementations to verify a request flow belong here, as do tests of real network, filesystem, log-export, and database interactions. SeaORM's `MockDatabase` replaces the database driver rather than the repositories and application services; its presence alone does not determine the test type either. Classify tests by the behavior and component boundary they exercise.

Run unit tests:

```powershell
cargo test --workspace --lib
```

Run integration tests that do not require a database:

```powershell
cargo test -p identity --test http --test network --test filesystem --test observability
cargo test -p identity --features oidc-conformance --test http
```

With Helm installed, verify rendered Chart configuration through the actual
production file loader in both TLS modes (no database or cluster access):

```powershell
cargo test -p identity --test helm_configuration -- --ignored
```

- `http/`: production HTTP/GraphQL routes, authorization interactions, protocol errors, CORS, and discovery metadata
- `network/`: HTTP response limits and redirects, logout notifications, and HTTPS password checks with a local certificate
- `filesystem/`: TLS files and workload credential loading
- `observability.rs`: initialization through the public entry point inside an async runtime, actual OTLP export, and shutdown
- `repository_behavior.rs`: query isolation, lifecycle checks, cursor pagination, settings and profile updates, and concurrent single-use redemption
- `repository_security.rs`: password revocation, login concurrency, audit persistence, and transaction rollback
- `common/`: a separate temporary schema for each database test, initialized through the normal migration entry point and cleaned up afterward, including on assertion failures
- `support/`: shared integration fixtures, including the production Login installer process; temporary files are created under `.data/integration-tests/` and cleaned up automatically

Set `IDENTITY_TEST_DATABASE_URL` from `DATABASE_URL` in the repository-root `.env`. Do not print connection credentials. Each test runs in its own temporary schema and does not use or clear existing business schemas.

```powershell
cargo test -p identity --test repository_behavior --test repository_security -- --ignored --test-threads=1
# The installer uses its own temporary schema and preserves existing data.
cargo test -p identity --test installation -- --ignored
```

To also run the built production Login installer against that real service and
temporary schema, first run `pnpm build:login` and set
`IDENTITY_TEST_LOGIN_NODE` to the absolute Node executable path. The test starts
`apps/login/production-server.mjs`, which imports `.output/server/index.mjs`, so
both the build output and Node must be present. The same installation test then
verifies the installer without public-address environment variables, Chinese
field errors, correction and resubmission, and readiness after installation. It
starts and stops its own local processes; it does not use a deployed Login
instance.

## Console container verification

With Docker running, build and verify the production Console image:

```sh
docker build -f deploy/docker/console.Dockerfile -t identity-console:local .
python3 tests/deployment/console-container.py identity-console:local
```

The check runs the actual image against a temporary local configuration server
using generated test credentials. It covers startup retries, runtime JSON,
read-only/non-root operation, HTTP/HTTPS and custom listener ports, TLS certificate
validation and startup failures, SPA routing, caching, sanitized callback logs,
and rejection of invalid configuration. OpenSSL must be available to generate
temporary test certificates. It removes its containers and temporary
credentials afterward and does not access a database or a deployed instance.
The image publishing workflow runs it for each native platform image.
