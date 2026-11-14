# GraphQL contract artifacts

This directory holds artifacts exported from the server, not hand-written
documentation. The API itself — transport, conventions, access requirements,
pagination, limits, errors, and the management scope catalog — is documented in
the [GraphQL API reference](../docs/graphql.md).

| Artifact | Source of truth | Regenerate | Verify |
| --- | --- | --- | --- |
| `schema.graphql` | The executable async-graphql schema, including `@access` directives | `pnpm graphql:schema` | `pnpm graphql:check` |
| `management-scopes.json` | The management scope catalog in application code | `pnpm scopes:catalog` | `pnpm scopes:check` |
| `error-catalog.json` | The typed application error catalogs | `pnpm errors:catalog` | `pnpm errors:check` |
| `@identity/graphql-access` metadata | `schema.graphql` (introspection does not expose custom directives) | `pnpm graphql:schema` | `pnpm graphql:access:check` |
| Console operation types | `schema.graphql` and Console documents | `pnpm graphql:codegen` | `pnpm typecheck:console` |

Run the commands from the repository root after changing a resolver, an access
policy, an error code, or a management scope. A stale export fails the matching
`*:check` in CI; do not edit these files by hand.

The generated error catalog also lists the numeric `code` and `kind` for every
application error, which is what clients receive in GraphQL error extensions.
The generated scope catalog is the authoritative list of reservable management
scopes; the same entries appear as a table in the
[GraphQL API reference](../docs/graphql.md#management-scope-catalog).

Persistence and auditing are described in the
[authorization model](../docs/authorization.md#audit): migrations carry structure,
the seed entry point initializes trusted definitions, and repository transactions
write authorization, revocation, and audit changes in Rust rather than in
database triggers.
