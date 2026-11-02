import {
  Kind,
  parse,
  valueFromASTUntyped,
  type DirectiveNode,
  type DocumentNode,
  type FragmentDefinitionNode,
  type OperationDefinitionNode,
  type SelectionSetNode,
  type ValueNode,
} from 'graphql'

import { schemaMetadata as defaultSchema } from './schema'
import type {
  AccessPolicy,
  PreflightContext,
  PreflightResult,
  PreflightStatus,
  SchemaMetadata,
} from './types'

const DEFAULT_MAX_AGE = 300
const DEFAULT_ELEVATED_MAX_AGE = 3_600
const MAX_SELECTION_DEPTH = 64

interface AuthRequirement {
  aal2: boolean
  recent: boolean
  maxAge?: number
  /** ACCOUNT_SECURITY could not be resolved from the available context. */
  unresolved: boolean
}

interface Outcome {
  /** Scopes required on every possible execution path. */
  requiredScopes: Set<string>
  /** Scopes that are only required on some possible runtime branch. */
  uncertainScopes: Set<string>
  auth: AuthRequirement
  requiresUser: boolean
  unknown: boolean
}

interface EvaluationContext {
  schema: SchemaMetadata
  scopeSet: ReadonlySet<string>
  acr?: string
  authTime?: number
  user?: boolean
  mfaEnabled?: boolean
  now: number
  variables?: Record<string, unknown>
  defaults: ReadonlyMap<string, unknown>
  fragments: ReadonlyMap<string, FragmentDefinitionNode>
}

interface Known<T> {
  known: boolean
  value?: T
}

const NOT_KNOWN: Known<never> = { known: false }

function noAuth(): AuthRequirement {
  return { aal2: false, recent: false, unresolved: false }
}

function combineAuth(a: AuthRequirement, b: AuthRequirement): AuthRequirement {
  const maxAge =
    a.maxAge === undefined
      ? b.maxAge
      : b.maxAge === undefined
        ? a.maxAge
        : Math.min(a.maxAge, b.maxAge)
  const combined: AuthRequirement = {
    aal2: a.aal2 || b.aal2,
    recent: a.recent || b.recent,
    unresolved: a.unresolved || b.unresolved,
  }
  if (maxAge !== undefined) combined.maxAge = maxAge
  return combined
}

function emptyOutcome(): Outcome {
  return {
    requiredScopes: new Set(),
    uncertainScopes: new Set(),
    auth: noAuth(),
    requiresUser: false,
    unknown: false,
  }
}

function copyOutcome(outcome: Outcome): Outcome {
  return {
    requiredScopes: new Set(outcome.requiredScopes),
    uncertainScopes: new Set(outcome.uncertainScopes),
    auth: combineAuth(outcome.auth, noAuth()),
    requiresUser: outcome.requiresUser,
    unknown: outcome.unknown,
  }
}

function combineOutcome(a: Outcome, b: Outcome): Outcome {
  const requiredScopes = new Set(a.requiredScopes)
  for (const scope of b.requiredScopes) requiredScopes.add(scope)
  const uncertainScopes = new Set(a.uncertainScopes)
  for (const scope of b.uncertainScopes) uncertainScopes.add(scope)
  return {
    requiredScopes,
    uncertainScopes,
    auth: combineAuth(a.auth, b.auth),
    requiresUser: a.requiresUser || b.requiresUser,
    unknown: a.unknown || b.unknown,
  }
}

function unknownOutcome(base: Outcome): Outcome {
  const outcome = copyOutcome(base)
  outcome.unknown = true
  return outcome
}

function isAal2(acr: string | undefined): boolean {
  return acr === 'aal2'
}

/** A future auth_time is not fresh either; it cannot be a negative age. */
function isFresh(authTime: number | undefined, maxAge: number, now: number): boolean {
  if (authTime === undefined || !Number.isFinite(authTime) || authTime < 0) return false
  if (authTime > now) return false
  return now - authTime <= maxAge
}

function sortedScopes(outcome: Outcome): string[] {
  return Array.from(
    new Set([...outcome.requiredScopes, ...outcome.uncertainScopes]),
  ).sort()
}

function selectOperation(
  document: DocumentNode,
  operationName: string | undefined,
): OperationDefinitionNode | undefined {
  const operations: OperationDefinitionNode[] = []
  for (const definition of document.definitions) {
    if (definition.kind === Kind.OPERATION_DEFINITION) operations.push(definition)
  }

  if (operationName !== undefined) {
    const matches = operations.filter(
      (operation) => operation.name?.value === operationName,
    )
    return matches.length === 1 ? matches[0] : undefined
  }

  return operations.length === 1 ? operations[0] : undefined
}

function collectFragments(
  document: DocumentNode,
): Map<string, FragmentDefinitionNode> | undefined {
  const fragments = new Map<string, FragmentDefinitionNode>()
  for (const definition of document.definitions) {
    if (definition.kind !== Kind.FRAGMENT_DEFINITION) continue
    const name = definition.name.value
    if (fragments.has(name)) return undefined
    fragments.set(name, definition)
  }
  return fragments
}

export function createPreflight(schema: SchemaMetadata) {
  function policyAuth(policy: AccessPolicy, context: EvaluationContext): AuthRequirement {
    const maxAge = policy.maxAge ?? DEFAULT_MAX_AGE
    switch (policy.authentication) {
      case 'SESSION':
        return noAuth()
      case 'AAL2':
        return { aal2: true, recent: false, unresolved: false }
      case 'RECENT':
        return { aal2: false, recent: true, maxAge, unresolved: false }
      case 'RECENT_AAL2':
        return { aal2: true, recent: true, maxAge, unresolved: false }
      case 'ACCOUNT_SECURITY': {
        if (context.mfaEnabled === true) {
          // AAL2 is the elevated assurance path and uses the elevated window.
          return {
            aal2: true,
            recent: true,
            maxAge: policy.elevatedMaxAge ?? DEFAULT_ELEVATED_MAX_AGE,
            unresolved: false,
          }
        }
        if (context.mfaEnabled === false) {
          return { aal2: false, recent: true, maxAge, unresolved: false }
        }
        // Unknown factor state can be proved only within both possible time
        // windows. Higher assurance does not extend an ordinary time window.
        const elevatedMaxAge = policy.elevatedMaxAge ?? DEFAULT_ELEVATED_MAX_AGE
        if (isAal2(context.acr) && isFresh(context.authTime, Math.min(maxAge, elevatedMaxAge), context.now)) {
          return noAuth()
        }
        return { aal2: false, recent: false, unresolved: true }
      }
    }
  }

  function addPolicies(
    base: Outcome,
    policies: readonly AccessPolicy[],
    context: EvaluationContext,
  ): Outcome {
    const requiredScopes = new Set(base.requiredScopes)
    let auth = base.auth
    let requiresUser = base.requiresUser
    for (const policy of policies) {
      for (const scope of policy.scopes) requiredScopes.add(scope)
      // Management machine grants are checked separately by the server and
      // never carry human ACR/auth_time. A user-only policy still rejects them.
      if (context.user !== false || policy.userOnly) {
        auth = combineAuth(auth, policyAuth(policy, context))
      }
      requiresUser = requiresUser || policy.userOnly
    }
    return {
      requiredScopes,
      uncertainScopes: new Set(base.uncertainScopes),
      auth,
      requiresUser,
      unknown: base.unknown,
    }
  }

  function authStatus(
    auth: AuthRequirement,
    context: EvaluationContext,
  ): 'ok' | 'reauth' | 'unresolved' {
    if (auth.aal2 && !isAal2(context.acr)) return 'reauth'
    if (auth.recent && (context.acr === undefined || !isFresh(context.authTime, auth.maxAge ?? DEFAULT_MAX_AGE, context.now))) {
      return 'reauth'
    }
    if (auth.unresolved) return 'unresolved'
    return 'ok'
  }

  function classify(outcome: Outcome, context: EvaluationContext): PreflightStatus {
    const missing = Array.from(outcome.requiredScopes).some(
      (scope) => !context.scopeSet.has(scope),
    )
    if (missing) return 'forbidden'
    if (outcome.requiresUser) {
      if (context.user === false) return 'forbidden'
      if (context.user !== true) return 'unknown'
    }
    const auth = authStatus(outcome.auth, context)
    if (auth === 'reauth') return 'reauthentication'
    if (outcome.unknown || auth === 'unresolved') return 'unknown'
    return 'allowed'
  }

  function typeApplies(runtimeTypeName: string, condition: string): boolean {
    if (runtimeTypeName === condition) return true
    const runtime = schema.types[runtimeTypeName]
    if (runtime?.interfaces.includes(condition)) return true
    const conditionType = schema.types[condition]
    return conditionType?.possibleTypes.includes(runtimeTypeName) === true
  }

  function variableValue(
    context: EvaluationContext,
    name: string,
  ): Known<unknown> {
    if (
      context.variables &&
      Object.prototype.hasOwnProperty.call(context.variables, name)
    ) {
      const value = context.variables[name]
      if (value !== undefined) return { known: true, value }
    }
    if (context.defaults.has(name)) {
      return { known: true, value: context.defaults.get(name) }
    }
    return NOT_KNOWN
  }

  function conditionValue(
    context: EvaluationContext,
    node: ValueNode,
  ): Known<unknown> {
    if (node.kind === Kind.BOOLEAN) return { known: true, value: node.value }
    if (node.kind === Kind.NULL) return { known: true, value: null }
    if (node.kind === Kind.VARIABLE) return variableValue(context, node.name.value)
    return NOT_KNOWN
  }

  function directiveCondition(
    context: EvaluationContext,
    directives: readonly DirectiveNode[] | undefined,
  ): 'include' | 'exclude' | 'unknown' {
    let included = true
    let unknown = false
    for (const directive of directives ?? []) {
      const name = directive.name.value
      if (name !== 'skip' && name !== 'include') continue
      const argument = directive.arguments?.find((entry) => entry.name.value === 'if')
      if (!argument) {
        unknown = true
        continue
      }
      const condition = conditionValue(context, argument.value)
      if (!condition.known || typeof condition.value !== 'boolean') {
        unknown = true
        continue
      }
      if (name === 'skip' && condition.value) included = false
      if (name === 'include' && !condition.value) included = false
    }
    if (!included) return 'exclude'
    return unknown ? 'unknown' : 'include'
  }

  function evaluateReturnType(
    selectionSet: SelectionSetNode,
    returnTypeName: string,
    inherited: Outcome,
    context: EvaluationContext,
    fragmentStack: readonly string[],
    depth: number,
  ): Outcome {
    if (depth > MAX_SELECTION_DEPTH) return unknownOutcome(inherited)
    const type = schema.types[returnTypeName]
    if (!type) return unknownOutcome(inherited)

    if (type.kind === 'OBJECT') {
      return evaluateSelectionSet(
        selectionSet,
        returnTypeName,
        returnTypeName,
        inherited,
        context,
        fragmentStack,
        depth,
      )
    }

    if (type.kind === 'INTERFACE' || type.kind === 'UNION') {
      if (type.possibleTypes.length === 0) return unknownOutcome(inherited)
      const branches = type.possibleTypes.map((runtimeTypeName) =>
        evaluateSelectionSet(
          selectionSet,
          returnTypeName,
          runtimeTypeName,
          inherited,
          context,
          fragmentStack,
          depth,
        ),
      )
      return combineBranches(branches, inherited, context)
    }

    return unknownOutcome(inherited)
  }

  function combineBranches(
    branches: readonly Outcome[],
    inherited: Outcome,
    context: EvaluationContext,
  ): Outcome {
    if (branches.length === 0) return unknownOutcome(inherited)

    const statuses = new Set(branches.map((branch) => classify(branch, context)))
    if (statuses.size === 1) {
      return branches.reduce((combined, branch) => combineOutcome(combined, branch))
    }

    // Different runtime types produce different authorization outcomes. Do not
    // turn a branch-specific denial into a universal denial or prompt. Keep the
    // unconditional parent requirements and defer the branch decision.
    const combined = branches.reduce((result, branch) => combineOutcome(result, branch))
    const requiredScopes = new Set(inherited.requiredScopes)
    const uncertainScopes = new Set(inherited.uncertainScopes)
    for (const scope of combined.requiredScopes) {
      if (!requiredScopes.has(scope)) uncertainScopes.add(scope)
    }
    for (const scope of combined.uncertainScopes) {
      if (!requiredScopes.has(scope)) uncertainScopes.add(scope)
    }
    return {
      requiredScopes,
      uncertainScopes,
      auth: inherited.auth,
      requiresUser: inherited.requiresUser,
      unknown: true,
    }
  }

  function evaluateSelectionSet(
    selectionSet: SelectionSetNode,
    staticTypeName: string,
    runtimeTypeName: string,
    inherited: Outcome,
    context: EvaluationContext,
    fragmentStack: readonly string[],
    depth: number,
  ): Outcome {
    if (depth > MAX_SELECTION_DEPTH) return unknownOutcome(inherited)

    const type = schema.types[staticTypeName]
    if (!type) return unknownOutcome(inherited)

    let outcome = copyOutcome(inherited)

    for (const selection of selectionSet.selections) {
      if (selection.kind === Kind.FIELD) {
        if (selection.name.value === '__typename') continue

        const condition = directiveCondition(context, selection.directives)
        if (condition === 'exclude') continue
        if (condition === 'unknown') {
          outcome.unknown = true
          continue
        }

        const metadata = type.fields[selection.name.value]
        if (!metadata) {
          outcome.unknown = true
          continue
        }

        const next = addPolicies(inherited, metadata.policies, context)
        outcome = combineOutcome(outcome, next)

        if (selection.selectionSet) {
          outcome = combineOutcome(
            outcome,
            evaluateReturnType(
              selection.selectionSet,
              metadata.returnType,
              next,
              context,
              fragmentStack,
              depth + 1,
            ),
          )
        } else if (schema.types[metadata.returnType]) {
          // An object-like field without a selection set is invalid; defer it.
          outcome.unknown = true
        }
        continue
      }

      if (selection.kind === Kind.INLINE_FRAGMENT) {
        const condition = directiveCondition(context, selection.directives)
        if (condition === 'exclude') continue
        if (condition === 'unknown') {
          outcome.unknown = true
          continue
        }

        const conditionName = selection.typeCondition?.name.value
        if (conditionName !== undefined) {
          if (!schema.types[conditionName]) {
            outcome.unknown = true
            continue
          }
          if (!typeApplies(runtimeTypeName, conditionName)) continue
        }

        outcome = combineOutcome(
          outcome,
          evaluateSelectionSet(
            selection.selectionSet,
            conditionName ?? staticTypeName,
            runtimeTypeName,
            inherited,
            context,
            fragmentStack,
            depth + 1,
          ),
        )
        continue
      }

      const condition = directiveCondition(context, selection.directives)
      if (condition === 'exclude') continue
      if (condition === 'unknown') {
        outcome.unknown = true
        continue
      }

      const fragmentName = selection.name.value
      if (fragmentStack.includes(fragmentName)) {
        outcome.unknown = true
        continue
      }
      const fragment = context.fragments.get(fragmentName)
      if (!fragment) {
        outcome.unknown = true
        continue
      }
      const conditionName = fragment.typeCondition.name.value
      if (!schema.types[conditionName]) {
        outcome.unknown = true
        continue
      }
      if (!typeApplies(runtimeTypeName, conditionName)) continue

      outcome = combineOutcome(
        outcome,
        evaluateSelectionSet(
          fragment.selectionSet,
          conditionName,
          runtimeTypeName,
          inherited,
          context,
          [...fragmentStack, fragmentName],
          depth + 1,
        ),
      )
    }

    return outcome
  }

  return function preflightOperation(
    document: string,
    variables: Record<string, unknown> | undefined,
    preflightContext: PreflightContext,
    operationName?: string,
  ): PreflightResult {
    let parsed: DocumentNode
    try {
      parsed = parse(document)
    } catch {
      return { status: 'unknown', requiredScopes: [] }
    }

    const operation = selectOperation(parsed, operationName)
    if (!operation) return { status: 'unknown', requiredScopes: [] }

    const fragments = collectFragments(parsed)
    if (!fragments) return { status: 'unknown', requiredScopes: [] }

    let rootTypeName: string
    if (operation.operation === 'query') {
      rootTypeName = schema.queryTypeName
    } else if (operation.operation === 'mutation') {
      if (!schema.mutationTypeName) return { status: 'unknown', requiredScopes: [] }
      rootTypeName = schema.mutationTypeName
    } else {
      return { status: 'unknown', requiredScopes: [] }
    }

    if (!schema.types[rootTypeName]) return { status: 'unknown', requiredScopes: [] }

    const defaults = new Map<string, unknown>()
    try {
      for (const definition of operation.variableDefinitions ?? []) {
        if (definition.defaultValue) {
          defaults.set(
            definition.variable.name.value,
            valueFromASTUntyped(definition.defaultValue),
          )
        }
      }
    } catch {
      return { status: 'unknown', requiredScopes: [] }
    }

    const context: EvaluationContext = {
      schema,
      scopeSet: new Set(preflightContext.scopes),
      acr: preflightContext.acr,
      authTime: preflightContext.authTime,
      user: preflightContext.user,
      mfaEnabled: preflightContext.mfaEnabled,
      now: preflightContext.now ?? Math.floor(Date.now() / 1_000),
      variables,
      defaults,
      fragments,
    }

    const outcome = evaluateSelectionSet(
      operation.selectionSet,
      rootTypeName,
      rootTypeName,
      emptyOutcome(),
      context,
      [],
      0,
    )

    const status = classify(outcome, context)
    const result: PreflightResult = {
      status,
      requiredScopes: sortedScopes(outcome),
    }
    if (status === 'reauthentication') {
      if (outcome.auth.aal2) result.acrValues = 'aal2'
      if (outcome.auth.recent) result.maxAge = outcome.auth.maxAge ?? DEFAULT_MAX_AGE
    }
    return result
  }
}

export const preflightOperation = createPreflight(defaultSchema)
