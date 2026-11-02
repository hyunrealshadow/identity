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

- `http/`: production HTTP/GraphQL routes, authorization interactions, protocol errors, CORS, and discovery metadata
- `network/`: HTTP response limits and redirects, logout notifications, and HTTPS password checks with a local certificate
- `filesystem/`: TLS files and workload credential loading
- `observability.rs`: initialization through the public entry point inside an async runtime, actual OTLP export, and shutdown
- `repository_behavior.rs`: query isolation, lifecycle checks, cursor pagination, settings and profile updates, and concurrent single-use redemption
- `repository_security.rs`: password revocation, login concurrency, audit persistence, and transaction rollback
- `common/`: a separate temporary schema for each database test, initialized through the normal migration entry point and cleaned up afterward, including on assertion failures
- `support/`: shared fixtures for integration tests that do not require a database; temporary files are created under `.data/integration-tests/` and cleaned up automatically

Set `IDENTITY_TEST_DATABASE_URL` from `DATABASE_URL` in the repository-root `.env`, and set `IDENTITY_TEST_DATABASE_NAME` to the database name in that URL. Do not print connection credentials. The tests reject the production database `identity` and do not use or clear existing business schemas.

```powershell
cargo test -p identity --test repository_behavior --test repository_security -- --ignored --test-threads=1
```
