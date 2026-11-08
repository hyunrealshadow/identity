# Project Guide

## Architecture and Domain Language

- Identity is a self-hosted OAuth 2.0 authorization server and OpenID Connect provider. Preserve protocol behavior as well as account and instance-management behavior.
- Use `CONTEXT.md` for domain terminology. Update it alongside changes to concepts, invariants, authorization semantics, or user-visible responsibilities. Check the executable implementation when older design documents disagree; do not restore superseded models from planning notes.
- Keep the Rust workspace boundaries: `src/domain` defines domain models, invariants, and repository ports; `src/application` coordinates use cases; `src/infrastructure` implements persistence and external services; `src/web` handles HTTP/GraphQL transport; `src/boot` and the root executable compose the application and its lifecycle.
- Domain and application code must not depend on infrastructure or web implementations. Keep transport types and SeaORM entities out of domain contracts.
- Organize backend and frontend code by functional module. Keep related behavior together rather than expanding a shared miscellaneous directory.

## API Contracts and Authentication

- Use the single `/graphql` endpoint for account self-service and instance-management operations. Preserve the protocol and login-interaction endpoints needed by OAuth/OIDC and authentication flows; do not add parallel REST management APIs.
- GraphQL has flat functional query fields and explicitly named mutations, composed from modules in `src/web/graphql/schema/modules`. Do not introduce `viewer` or `management` wrapper namespaces.
- Use async-graphql input validators and guards for transport validation and admission checks. Application/domain checks and transactional repository checks remain authoritative for business invariants, ownership, and live authorization.
- Declare each GraphQL operation's required scopes, principal restrictions, assurance, and freshness through the existing `@access` directive mechanism. Keep protected nested fields covered as well. Derive declarations and enforcement from the same policies.
- Console and Login's account center share `packages/graphql-access` for operation-based preflight. Do not maintain independent frontend permission/freshness tables or infer requirements from operation names. Preflight improves interaction; it cannot prove target-dependent or live server conditions.
- Only start reauthentication when current authentication fails the actual requirement. Use the existing session and identity hint where possible. Ordinary login omits `prompt`; explicit account switching uses `prompt=select_account`.
- Treat MFA as an authentication-stage invariant: password is not an alternative once the flow enters MFA. Assurance and freshness are separate requirements.
- Reauthentication uses a browser popup, not an embedded iframe. Validate callback origin, state, window, and subject; reject stale-session results. Preserve form drafts on cancellation, and do not automatically replay a mutation after successful authentication.
- Keep issuer, Login, and Console public addresses independently configurable through existing settings. Keep the internal workload listener private and authenticated; do not expose workload credentials to browser code.
- Use Relay connection semantics for pagination: `first` with `after`, `last` with `before`, stable ordering with a unique tie-breaker, and accurate page information in both directions.

## Authorization Model

- A user is one identity for both ordinary access and instance administration. Administrative capability comes from effective permissions, not a separate account type or a privileged role name.
- Users receive roles directly or through group membership. Groups receive permissions through roles. Preserve all effective permission sources when evaluating or displaying access.
- Scope definitions belong directly to an API resource through `scope.resource_id`; protocol/identity scopes may have no resource. Client scope assignments and role permissions reference the same definitions. Do not reintroduce parallel resource-permission catalogs or redundant management-policy switches.
- Client-credentials access represents the client itself. User access additionally depends on the user's live effective permissions. Enforce resource/audience, client-allowed scope, token scope, and applicable authentication requirements together; consent does not create permissions.
- Use singular resource segments in scope codes, including `management.user`, `management.group`, `management.role`, and `management.permission`. Explicit `.*` selectors may occur at any hierarchy level and select registered descendants only; an exact code is not an implicit prefix grant.
- Built-in groups, roles, and scopes have protected definitions identified by `built_in`. Do not authorize by display names or add role/group machine keys to recognize presets. Built-in group membership is managed separately from its immutable definition.
- Custom roles may reference built-in scopes. Editing a role or group does not confer arbitrary delegation rights: enforce the actor's delegation ceiling and the explicit permission-delegation capability.
- Preserve the last recoverable authorization administrator under concurrent changes. Recovery depends on actual access and credentials, not merely membership in a named preset.
- `version` is a UUID used only for optimistic locking. Compare the submitted version and replace it on successful changes. Do not add revision counters, duplicate version fields, or use row-version equality as proof of authority.
- Evaluate credential authority from live authorization, semantic dependency fingerprints, and permanent withdrawal facts. Display/profile edits must not invalidate grants; re-enabling an object or regranting access must not revive withdrawn credentials.

## Persistence, Migrations, and Audit

- Follow `migration/AGENTS.md` for migration implementation and naming. Use one table per migration, action-based names, SeaORM/SeaQuery builders, and `DeriveIden` identifiers. Do not use raw SQL for changes those builders can express.
- For undeployed features, put the final schema in the initial definitions and update existing seed code instead of preserving development-only compatibility steps. Preserve deployed migration identities and necessary upgrade paths.
- Put business rules, authorization calculations, and audit writes in Rust, not database functions or triggers. Initialize preset data through `src/infrastructure/database/seed`; repeated seed execution must not restore revoked user grants.
- Use foreign keys and appropriate dependent-row lifecycles to prevent dangling references, including OIDC configuration, credentials, platforms, and origins when a client is removed.
- Persist semantic security audit records with their own stable `oid` in the same transaction as the business change. Audit failure must roll back the change. Preserve optimistic locks, live authorization, and recovery protections without requiring a manually entered reason or adding an approval workflow.

## Frontend and Presentation

- `apps/login` owns sign-in, consent, installation, and account self-service. `apps/console` is a static instance-management frontend; it links to the account center from the top-right menu rather than reimplementing personal account management.
- Use TanStack file/folder routes and functional module folders. Route files compose module behavior; avoid mixing every page, query, and component into one large directory.
- Both frontends use shadcn components (Base UI, preset `bIkeymG`) shared from `packages/ui` through `@identity/ui/components/*` and `@identity/ui/globals.css`; add new ones with the shadcn CLI from `apps/login` so they land in `packages/ui`. Console follows Login's base theme and global radius tokens; do not add arbitrary per-page card radii or unnecessary card wrappers around tables.
- Login's sign-in flow (identifier, password, OTP, recovery code, consent, device, installation, sign-out, appearance) must work without JavaScript, except passkeys. Keep native `<form method="post">` and native inputs as the source of submitted values; JavaScript only enhances them.
- Interactive controls show a pointer cursor; the shared `globals.css` covers buttons and ARIA-role widgets, and shared shadcn items use `cursor-pointer` instead of `cursor-default`.
- Reuse the date field and base table in `packages/ui`. Application adapters provide the account locale, time zone, and translated labels; shared styles consume global theme and radius tokens. Keep row actions and authorization behavior in their functional modules.
- Present table row operations through the shared action dropdown. Functional modules still own action visibility, admission checks, navigation, and confirmation dialogs; keep dialog state mounted outside the menu so dismissing it cannot discard confirmation or form state.
- Dashboard content should be real, authorized instance aggregates. Missing permission or unavailable data must not become zero. Do not make authentication diagnostics, scopes, request/trace IDs, or deployment metadata the main dashboard content.
- Keep account summaries and two-letter avatar fallbacks consistent across applications. Offer explicit account switching through the existing account menu flow.
- Use layout-matched skeletons for page and tab loading so navigation does not replace content with a differently sized spinner panel. Keep empty states concise; do not add filler labels for unavailable values.
- Refresh an existing table with skeletons in its data rows only. Keep the header, tools, counts, and pagination mounted, preserve column widths and body height, and disable duplicate refreshes and page navigation until the request finishes.

## Localization, Errors, and Observability

- Localize every new page, control, validation message, empty/loading state, and user-visible backend error in the supported English and Simplified Chinese catalogs. Do not return raw internal errors or untranslated library validation text.
- Keep localized object fields consistent: `names` and `descriptions` are locale-to-text maps in persistence. Keep `name` and `description` as independent default text: the default name is required, translations are optional, and translation edits never overwrite defaults. Editable fields show separate default and translation inputs. Use the existing API conversion and language-selection editor. The viewing frontend chooses language and fallback; do not add `default_locale` to role, group, or permission definitions.
- Follow the authenticated user's locale, theme, and time-zone preferences in both applications. With no explicit preference, language follows the browser and time zone follows the system. Apply time zone to timestamps and calendar-day filters/aggregates, without shifting date-only values or elapsed durations.
- Keep Chinese explanatory Console copy concise and omit trailing full stops. Use ` - ` as the title separator rather than a centered dot.
- Extend the typed application error catalogs and existing localized transport mapping. Preserve structured field errors and real request/trace correlation; never fabricate backend identifiers for frontend preflight failures.
- Add meaningful spans and structured diagnostics through the existing tracing/observability infrastructure. Keep credentials, tokens, passwords, MFA secrets, and sensitive request bodies out of logs and traces. Correlation IDs belong in diagnostics and error details, not permanent page furniture.

## Testing Boundaries

- Keep only unit tests in `src/`.
- Place all integration tests in the repository-root `tests/` directory.
- Using a mock repository does not make a test an integration test. A test that isolates an application service or another component with fake/mock dependencies and verifies its own logic is still a unit test.
- Classify tests by the behavior and component boundary they exercise, not by the presence of mocks or a particular test utility.
- Real composed request flows and actual database, network, filesystem, or telemetry-export interactions belong in root `tests/`. Follow `tests/README.md` for suite entry points and isolated database setup; do not mount integration tests back into `src/` through path attributes.
- Prefer tests of observable behavior, failure recovery, concurrency, and security boundaries. Avoid tests that merely restate constants, count catalog entries, exercise trivial getters, compare generated strings to themselves, or mirror implementation details. Do not test migration SQL text or naming snapshots.
- Run checks appropriate to the changed boundary. Mock-based unit tests do not establish protocol or database correctness; use real runtime verification for authorization, withdrawal, audit rollback, and recovery changes, and report any unverified behavior explicitly.

## Contracts, Validation, and Working Data

- Executable schema and typed backend catalogs are the source of exported contracts. Regenerate affected artifacts with `pnpm graphql:schema`, `pnpm errors:catalog`, or `pnpm scopes:catalog`; regenerate Console operation types with `pnpm graphql:codegen` when needed. Do not hand-edit generated SDL, access metadata, or client types.
- Use the matching `pnpm graphql:check`, `pnpm errors:check`, and `pnpm scopes:check` commands for affected contracts. Common checks include `cargo fmt --all -- --check`, `cargo test --workspace --lib`, `pnpm typecheck:console`, and the affected application's test/build scripts. See `tests/README.md` for integration commands.
- The user's test database means the database configured in the root `.env`. Read the configuration without exposing credentials, and do not substitute another database for it. Keep verification data isolated and clean it up, and do not reset existing data without authorization.
- Keep private implementation plans, black-box reports, credentials, and local verification artifacts out of commits. Do not introduce reference identity-provider product names into committed source, comments, or documentation; private planning notes may retain reference links.
- Keep changes scoped to the requested work and preserve unrelated workspace edits. Update domain language, API contracts, seed, localization, tracing, and relevant verification together when a functional change affects them.
