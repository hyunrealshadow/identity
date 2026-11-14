# Identity documentation

[Back to the project README](../README.md)

Identity is a self-hosted OAuth 2.0 authorization server and OpenID Connect
provider with account self-service and instance management. This directory holds
the reference pages that describe behaviour independent of any one component.
Each application and deployment artifact keeps its own README for
component-specific setup.

## Start where your task starts

| If you need to… | Read |
| --- | --- |
| Deploy, configure, or operate an instance | [Deployment guide](../deploy/README.md) → [Helm chart](../deploy/helm/identity/README.md) → [Protocol reference](protocol.md) |
| Connect a client or resource server | [Protocol reference](protocol.md) → [Client policy](protocol.md#client-policy) |
| Implement sign-in, device, or step-up behaviour | [Authentication flows](authentication-flows.md) |
| Understand who may call what | [Authorization model](authorization.md) |
| Call or extend the management API | [GraphQL API](graphql.md) → [executable schema](../graphql/schema.graphql) |
| Work on sign-in, consent, or account pages | [Authentication flows](authentication-flows.md) → [Login guide](../apps/login/README.md) → [Security](security.md) |
| Work on the instance console | [Console guide](../apps/console/README.md) → [Authorization model](authorization.md) |
| Change persistence or seed data | [Migration rules](../migration/AGENTS.md) |
| Run or add tests | [Testing](testing.md) → [Test suites](../tests/README.md) |
| Check certification behaviour | [Conformance runner](../conformance/README.md) |

## Reference pages

| Document | Covers |
| --- | --- |
| [Protocol reference](protocol.md) | Identifiers, client policy, resource indicators (RFC 8707), pushed authorization requests (RFC 9126), endpoint inventory |
| [Authorization model](authorization.md) | Principals, resources and scopes, effective permissions, client authority, authentication requirements, delegation, recovery, credential authority, built-in definitions, audit |
| [GraphQL API](graphql.md) | Transport, schema conventions, `@access` requirements, pagination, limits, error envelope, management scope catalog, generated artifacts |
| [Authentication flows](authentication-flows.md) | Login stages, credential methods, assurance and freshness, consent, code and token exchange, device authorization, step-up, logout |
| [Security](security.md) | Password policy, multi-factor authentication, session protection, API authorization summary, security auditing, browser windows |
| [Testing](testing.md) | Suite selection, unit versus integration boundaries, isolated databases, contract checks, container verification |

## Component guides

| Document | Covers |
| --- | --- |
| [Login](../apps/login/README.md) | TanStack Start application, server-side session handling, passkeys, installer, account pages |
| [Console](../apps/console/README.md) | Static management frontend, runtime configuration endpoint, workload credentials, build |
| [Deployment](../deploy/README.md) | Docker Compose stack, images, environment variables, TLS, observability wiring |
| [Helm chart](../deploy/helm/identity/README.md) | Values model, Secrets, probes, NetworkPolicies, Gateway integration, multi-replica settings |
| [Raw manifests](../deploy/kubernetes/README.md) | Why the partial manifests were retired in favour of the chart |
| [Test suites](../tests/README.md) | Integration layout, isolated databases, how to run each suite |
| [Conformance](../conformance/README.md) | OpenID Foundation suite wiring, plans, and result handling |
| [Migration rules](../migration/AGENTS.md) | One table per migration, naming, builders only, no seed drift |
| [Schema contracts](../graphql/README.md) | How SDL, error catalog, scope catalog, and client types are generated |
| [Project guide](../AGENTS.md) | Architecture, domain language, and the rules that keep changes consistent |

## Durable decisions

These choices are old enough that changing them should be deliberate. The
rationale lives with the rule, so an implementation can be checked against the
reason it exists rather than against an adopted convention.

- **Authority comes from live relations.** Roles, groups, scopes, and resource
  state are evaluated when a request arrives. A stored version, a display name,
  or a session snapshot is never proof of authority.
  [Details](authorization.md#effective-permissions)
- **Every scope definition belongs to one resource.** Codes are unique within
  that resource; the same code elsewhere conveys nothing.
  [Details](authorization.md#resources-and-scopes)
- **The same `@access` declaration is published and enforced.** Schema
  directives are generated from the policy objects the server evaluates, so
  preflight and enforcement cannot drift.
  [Details](graphql.md#access-requirements)
- **Consent never creates permission.** A user can approve only the intersection
  of what the client may ask for and what the user currently holds.
  [Details](authorization.md#principals)
- **Delegation is capped by the actor's own permissions.** Granting, assigning,
  and client scope replacement all fit the pre-change ceiling; exceeding it
  needs explicit `management.permission.delegate` plus recent AAL2.
  [Details](authorization.md#delegation-ceiling)
- **Recovery is a capability, not a preset.** At least one enabled user with
  usable credentials must retain the full management set, re-checked in the same
  transaction before any authorization change commits.
  [Details](authorization.md#recovery-of-instance-authorization)
- **Audit writes share the business transaction.** A failed audit insert rolls
  back the change, and the audit store exposes append and read only.
  [Details](security.md#security-auditing)
- **Withdrawal is permanent.** Disabling, rotating, or revoking retires the
  artifacts issued under the old grant; re-granting access never revives them.
  [Details](authorization.md#credential-authority)
- **Reauthentication never replays a pending write.** The popup returns a
  result, the client restores the user's draft, and the user submits again.
  [Details](security.md#authentication-browser-windows)
- **A mock repository does not make a test an integration test.** Classification
  follows the boundary the test exercises, and real protocol or database
  behaviour is verified against real runtime pieces.
  [Details](testing.md#unit-tests-in-src)
- **Reasons are optional everywhere.** Management mutations accept a reason for
  the audit trail, but no operation requires one and no approval workflow gates
  a change. [Details](graphql.md#schema-conventions)

## How these pages are maintained

- The executable schema and typed backend catalogs are the source of truth for
  exported contracts. Regenerate affected artifacts with
  `pnpm graphql:schema`, `pnpm errors:catalog`, `pnpm scopes:catalog`, or
  `pnpm graphql:codegen`; never hand-edit generated SDL, access metadata, or
  client types.
- Code wins over stale prose. When an older design note disagrees with the
  implementation, correct the page here and leave the note alone.
- Reference pages are written in English; user-facing product text is localized
  separately in the application catalogs.
- Do not name specific identity-provider products as references in committed
  pages. Describe the behaviour instead.
- Implementation reports, black-box verification notes, and local plans are
  working notes rather than part of this reference set. Their durable outcomes
  belong in the pages above.
