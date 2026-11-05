import {
  preflightOperation,
  type PreflightResult,
} from '@identity/graphql-access'

import type { ReauthenticationOptions } from '#/lib/auth/context'
import { getAuthSession, type AuthSession } from '#/lib/auth/session'
import type { Locale } from '#/lib/i18n'
import {
  executeGraphQL,
  graphqlDocumentText,
  type DocumentSource,
  type GraphQLResult,
  type GraphQLStepUp,
} from '#/lib/graphql/transport'

/** One GraphQL request, including preflight, reauthentication and correlation. */
export type GraphQLRequester = <TData, TVariables>(
  document: string | DocumentSource<TData, TVariables>,
  variables: TVariables,
  operationName?: string,
  options?: { signal?: AbortSignal },
) => Promise<GraphQLResult<TData>>

type LocalFailureCode =
  'insufficient_scope' | 'insufficient_user_authentication'

export interface RequestableAccess {
  session: AuthSession
  scopes: readonly string[]
}

export interface GraphQLRequesterDependencies {
  graphqlUrl: string
  locale: Locale
  accessToken: () => string | null
  requireReauthentication: (
    challenge?: GraphQLStepUp,
    options?: ReauthenticationOptions,
  ) => Promise<void>
  requestable: RequestableAccess | null
  /** Localized copy used when preflight denies or challenges the request. */
  messages: { forbidden: string; stepUp: string }
}

function preflightStepUp(result: PreflightResult): GraphQLStepUp {
  const stepUp: GraphQLStepUp = { source: 'preflight', recoveryManaged: true }
  if (result.acrValues) stepUp.acrValues = result.acrValues
  if (result.maxAge !== undefined) stepUp.maxAge = result.maxAge
  if (result.requiredScopes.length > 0)
    stepUp.requiredScopes = result.requiredScopes
  return stepUp
}

function localFailure<TData>(
  code: LocalFailureCode,
  message: string,
  options: {
    forbidden: boolean
    stepUp?: GraphQLStepUp
    requiredScopes?: readonly string[]
  },
): GraphQLResult<TData> {
  return {
    data: null,
    errors: [
      {
        message,
        kind: options.forbidden
          ? 'authorization_error'
          : 'authentication_error',
        code,
        fields: [],
        ...(options.stepUp ? { stepUp: options.stepUp } : {}),
        ...(options.requiredScopes && options.requiredScopes.length > 0
          ? {
              extensions: {
                code,
                requiredScopes: [...options.requiredScopes],
              },
            }
          : {}),
      },
    ],
    failure: {
      kind: 'graphql',
      code,
      ...(options.stepUp ? { stepUp: options.stepUp } : {}),
    },
    partial: false,
    unauthorized: false,
    forbidden: options.forbidden,
    ...(options.stepUp ? { stepUp: options.stepUp } : {}),
  }
}

function abortIfRequested(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    throw new DOMException('The GraphQL request was aborted.', 'AbortError')
  }
}

/**
 * Builds the single request path shared by every query and mutation. The
 * dependencies are captured once per rendered provider; TanStack Query keeps
 * the resulting functions stable so a rerender cannot restart a request.
 */
export function createGraphQLRequester({
  graphqlUrl,
  locale,
  accessToken,
  requireReauthentication,
  requestable,
  messages,
}: GraphQLRequesterDependencies): GraphQLRequester {
  return async function request<TData, TVariables>(
    document: string | DocumentSource<TData, TVariables>,
    variables: TVariables,
    operationName?: string,
    options?: { signal?: AbortSignal },
  ): Promise<GraphQLResult<TData>> {
    abortIfRequested(options?.signal)
    const token = accessToken() ?? ''
    const session = getAuthSession()

    // A usable in-memory session is the only source of local scopes and
    // claims. An expired session is left to the existing transport and
    // central authentication flow instead of trusting stale capabilities.
    if (session && token) {
      let decision: PreflightResult | undefined
      try {
        decision = preflightOperation(
          graphqlDocumentText(document),
          variables as unknown as Record<string, unknown> | undefined,
          {
            scopes: session.grantedScopes,
            acr: session.claims.acr,
            authTime: session.claims.auth_time,
            user: true,
            now: Math.floor(Date.now() / 1_000),
          },
          operationName,
        )
      } catch {
        // Preflight must never turn a document it cannot understand into a
        // denial. The server remains authoritative for unknown input.
        decision = undefined
      }

      // A stale SSO login may have clipped write scopes from this token. Only
      // re-evaluate authentication when the same session's live snapshot says
      // those scopes are requestable; do not convert a real denial into MFA.
      if (
        decision?.status === 'forbidden' &&
        decision.requiredScopes.length &&
        requestable?.session === session &&
        decision.requiredScopes.every(
          (scope) =>
            session.grantedScopes.includes(scope) ||
            requestable.scopes.includes(scope),
        )
      ) {
        const eligible = preflightOperation(
          graphqlDocumentText(document),
          variables as unknown as Record<string, unknown> | undefined,
          {
            scopes: [...session.grantedScopes, ...requestable.scopes],
            acr: session.claims.acr,
            authTime: session.claims.auth_time,
            user: true,
            now: Math.floor(Date.now() / 1_000),
          },
          operationName,
        )
        if (eligible.status === 'reauthentication') decision = eligible
      }

      if (decision?.status === 'forbidden') {
        const code: LocalFailureCode =
          decision.requiredScopes.length > 0
            ? 'insufficient_scope'
            : 'insufficient_user_authentication'
        return localFailure<TData>(code, messages.forbidden, {
          forbidden: true,
          requiredScopes: decision.requiredScopes,
        })
      }

      if (decision?.status === 'reauthentication') {
        const stepUp = preflightStepUp(decision)
        // Claims can still look usable after a credential was withdrawn.
        // Confirm live SESSION access without submitting the pending operation.
        const checked = await executeGraphQL<
          { effectivePermissions: { __typename: string } },
          Record<string, never>
        >('query ConsoleAuthenticationCheck { effectivePermissions { __typename } }', {
          graphqlUrl,
          accessToken: token,
          locale,
          variables: {},
          ...(options?.signal ? { signal: options.signal } : {}),
        })
        abortIfRequested(options?.signal)
        if (getAuthSession() !== session) {
          return localFailure<TData>(
            'insufficient_user_authentication',
            messages.stepUp,
            { forbidden: false, stepUp },
          )
        }
        if (checked.unauthorized) {
          void requireReauthentication(undefined, {
            reason: 'unauthorized',
            requestId: checked.requestId,
            traceId: checked.traceId,
          })
        }
        if (
          checked.failure ||
          checked.errors.length ||
          !checked.data?.effectivePermissions
        ) {
          return { ...checked, data: null } as GraphQLResult<TData>
        }
        void requireReauthentication(stepUp, { reason: 'step_up' })
        return localFailure<TData>(
          'insufficient_user_authentication',
          messages.stepUp,
          { forbidden: false, stepUp, requiredScopes: decision.requiredScopes },
        )
      }
    }

    const result = await executeGraphQL<TData, TVariables>(document, {
      graphqlUrl,
      accessToken: token,
      locale,
      variables,
      operationName,
      ...(options?.signal ? { signal: options.signal } : {}),
    })
    abortIfRequested(options?.signal)

    // The request belongs to the session that sent it. An old response may
    // not restart recovery after a validated popup has replaced that session.
    if (result.stepUp) result.stepUp.recoveryManaged = true
    if (getAuthSession() !== session) return result

    // A real permission denial has no step-up challenge and is returned to
    // the page as an actual denial. Only an authentication challenge or an
    // ordinary unauthorized response starts the single central redirect.
    if (result.stepUp) {
      void requireReauthentication(result.stepUp, {
        reason: 'step_up',
        requestId: result.requestId,
        traceId: result.traceId,
      })
    } else if (result.unauthorized) {
      void requireReauthentication(undefined, {
        reason: 'unauthorized',
        requestId: result.requestId,
        traceId: result.traceId,
      })
    }
    return result
  }
}
