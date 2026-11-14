# Testing

[Documentation index](README.md) · [GraphQL API](graphql.md) · [Authorization model](authorization.md)

Identity separates tests by the boundary they exercise, not by the tooling they
happen to use. A test that replaces a repository with a fake and checks a
service's own logic is a unit test. A test that runs a composed request flow, a
real database, a real filesystem layout, or a real telemetry export is an
integration test.

That rule decides where a test lives and what it proves. It also decides what it
must not claim: a green mock-based suite says nothing about protocol conformance,
authorization semantics, or persistence behaviour.

- [Pick the suite](#pick-the-suite)
- [Unit tests in `src/`](#unit-tests-in-src)
- [Integration suites in `tests/`](#integration-suites-in-tests)
- [Database-backed suites](#database-backed-suites)
- [Deployment and container checks](#deployment-and-container-checks)
- [Generated contracts](#generated-contracts)
- [Conformance runs](#conformance-runs)
- [What to verify by hand](#what-to-verify-by-hand)

## Pick the suite

| You changed… | Run |
| --- | --- |
| Domain rules, application services, validators | `cargo test --workspace --lib` |
| HTTP routes, GraphQL schema, authorize/consent/continuation, metadata | `cargo test -p identity --test http` |
| Outbound HTTP peers, back-channel logout, breach checks | `cargo test -p identity --test network` |
| TLS material, workload credentials | `cargo test -p identity --test filesystem` |
| Tracing and OTLP export | `cargo test -p identity --test observability` |
| Repository behaviour and effective permissions | `cargo test -p identity --test repository_behavior -- --ignored --test-threads=1` |
| Security boundaries in client and instance management | `cargo test -p identity --test repository_security -- --ignored --test-threads=1` |
| Helm chart rendering and the loaded configuration | `cargo test -p identity --test helm_configuration -- --ignored` |
| First-install bootstrap | `cargo test -p identity --test installation -- --ignored` |
| Console UI and its operation types | `pnpm test:console`, `pnpm typecheck:console` |
| Generated contracts | `pnpm graphql:check`, `pnpm errors:check`, `pnpm scopes:check` |

## Unit tests in `src/`

Unit tests live beside the code they exercise. They may use an in-memory
database driver, a fake clock, or a hand-written port implementation, because
those replace infrastructure rather than the component under test.

Keep them about behaviour: an invariant that can be violated, a failure that must
be recovered, a boundary that must be enforced. A test that restates a constant,
counts catalog entries, calls a trivial getter, or compares a generated string to
itself documents nothing and breaks on harmless refactors.

## Integration suites in `tests/`

Each file under `tests/` is its own binary and can be run on its own. They are not
declared in `Cargo.toml`; the convention in this repository relies on automatic
discovery.

| Suite | What it starts | What it proves |
| --- | --- | --- |
| `http` | The composed web application with in-memory persistence fixtures | Authorize, consent, continuation, registration, CORS, token errors, GraphQL, metadata, workload runtime |
| `network` | Local TCP peers and a local HTTP server | Outbound document fetching rules (redirect, size, timeout), back-channel logout delivery, breach-check integration |
| `filesystem` | Temporary directories | TLS material loading and workload credential files |
| `observability` | A local OTLP collector | Spans and logs actually leave the process |
| `repository_behavior` | A real PostgreSQL database | Repository behaviour and effective-permission totals |
| `repository_security` | A real PostgreSQL database | Security boundaries of client and instance management |
| `helm_configuration` | Helm and the production configuration loader | Rendered chart values load as a valid configuration in both TLS modes |
| `installation` | A real database and the first-install path | Bootstrap with real settings, credentials, and client registration |

The `http` suite also carries a conformance variant, enabled with the
`oidc-conformance` feature:

```sh
cargo test -p identity --features oidc-conformance --test http
```

That build relaxes selected protocol checks for a certification harness. It is
not a production configuration and should not be used to justify production
behaviour.

## Database-backed suites

The suites that need a real database read `IDENTITY_TEST_DATABASE_URL` from the
root `.env`. Each test creates its own temporary schema through the normal
migration entry point, runs inside it, and drops it afterwards, including when an
assertion fails. Existing data in that database is not reset or truncated.

- Run the ignored database suites with `--test-threads=1`; they are designed for
  an explicitly configured database, not for parallel local runs.
- The URL is a test credential. Do not point it at a database whose data you are
  not prepared to isolate.
- If a suite cannot reach its database, fix the configuration rather than
  swapping in another database; tests and development are expected to share the
  configured instance.

## Deployment and container checks

The Console container is verified as a container, not through the UI test suite:

```sh
docker build -f deploy/docker/console.Dockerfile -t identity-console:local .
python3 tests/deployment/console-container.py identity-console:local
```

The script checks startup retries, runtime configuration, the read-only non-root
filesystem, HTTP and HTTPS with custom ports, TLS validation, SPA routing,
caching, sanitized callback logging, and invalid configuration handling. It needs
OpenSSL and cleans up after itself.

The Helm suite renders the chart and feeds the result through the production
configuration loader in both TLS modes, so a broken values template fails as a
configuration error rather than at deploy time. It needs Helm but no cluster and
no database.

## Generated contracts

Contracts are exported from the executable schema and the typed backend
catalogs. Regenerate, then check that the working tree matches:

```sh
pnpm graphql:schema     # SDL plus @access metadata
pnpm errors:catalog     # error catalog
pnpm scopes:catalog     # management scope catalog
pnpm graphql:codegen    # Console operation types

pnpm graphql:check
pnpm errors:check
pnpm scopes:check
```

Never hand-edit `graphql/schema.graphql`, `graphql/error-catalog.json`,
`graphql/management-scopes.json`, the generated access metadata, or the Console
operation types. See [graphql/README.md](../graphql/README.md) for the artifact
map.

## Conformance runs

The certification harness is its own environment. Its Compose stack builds the
server with the conformance features, runs it as `APP_ENV=conformance`, and
drives the OpenID Foundation suite against it. The runner exits successfully even
when individual tests fail unless `--exit-on-failure` is passed; see
[conformance/README.md](../conformance/README.md).

## What to verify by hand

Some changes need real runtime evidence, not a passing mock suite:

- authorization and withdrawal semantics, including re-granting access;
- audit rollback when the audit insert fails;
- recovery protection under concurrent authorization changes;
- session revocation effects on codes, refresh tokens, and access tokens;
- step-up and popup reauthentication behaviour.

When a behaviour was not verified, say so explicitly in the change description
rather than implying coverage.

## Related pages

- [Test suites README](../tests/README.md) — exact commands and suite entry points
- [Conformance runner](../conformance/README.md) — plans, environment, result handling
- [GraphQL API](graphql.md) — what the output contracts describe
- [Authorization model](authorization.md) — the semantics worth verifying
