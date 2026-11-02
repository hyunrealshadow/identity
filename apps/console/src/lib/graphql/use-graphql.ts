import { useCallback } from 'react'

import { preflightOperation, type PreflightResult } from '@identity/graphql-access'

import { useAuth } from '#/lib/auth/context'
import { getAuthSession } from '#/lib/auth/session'
import { useLocale } from '#/lib/i18n'
import { useRuntimeConfig } from '#/lib/runtime-config'
import {
  executeGraphQL,
  graphqlDocumentText,
  type DocumentSource,
  type GraphQLFailure,
  type GraphQLIssue,
  type GraphQLResult,
  type GraphQLStepUp,
} from '#/lib/graphql/transport'

export type GraphQLRequest = <TData, TVariables>(
  document: string | DocumentSource<TData, TVariables>,
  variables: TVariables,
  operationName?: string,
) => Promise<GraphQLResult<TData>>

type LocalFailureCode = 'insufficient_scope' | 'insufficient_user_authentication'

function preflightStepUp(result: PreflightResult): GraphQLStepUp {
  const stepUp: GraphQLStepUp = { source: 'preflight', recoveryManaged: true }
  if (result.acrValues) stepUp.acrValues = result.acrValues
  if (result.maxAge !== undefined) stepUp.maxAge = result.maxAge
  if (result.requiredScopes.length > 0) stepUp.requiredScopes = result.requiredScopes
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
  const issue: GraphQLIssue = {
    message,
    kind: options.forbidden ? 'authorization_error' : 'authentication_error',
    code,
    fields: [],
  }
  if (options.stepUp) issue.stepUp = options.stepUp
  if (options.requiredScopes && options.requiredScopes.length > 0) {
    issue.extensions = { code, requiredScopes: [...options.requiredScopes] }
  }

  const failure: GraphQLFailure = { kind: 'graphql', code }
  if (options.stepUp) failure.stepUp = options.stepUp

  return {
    data: null,
    errors: [issue],
    failure,
    partial: false,
    unauthorized: false,
    forbidden: options.forbidden,
    ...(options.stepUp ? { stepUp: options.stepUp } : {}),
  }
}

export function useGraphQL(): GraphQLRequest {
  const config = useRuntimeConfig()
  const { locale, t } = useLocale()
  const { accessToken, requireReauthentication } = useAuth()

  return useCallback(
    function request<TData, TVariables>(
      document: string | DocumentSource<TData, TVariables>,
      variables: TVariables,
      operationName?: string,
    ): Promise<GraphQLResult<TData>> {
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

        if (decision?.status === 'forbidden') {
          const code: LocalFailureCode =
            decision.requiredScopes.length > 0
              ? 'insufficient_scope'
              : 'insufficient_user_authentication'
          return Promise.resolve(
            localFailure<TData>(code, t('forbiddenDescription'), {
              forbidden: true,
              requiredScopes: decision.requiredScopes,
            }),
          )
        }

        if (decision?.status === 'reauthentication') {
          const stepUp = preflightStepUp(decision)
          // Claims can still look usable after a credential was withdrawn.
          // Confirm live SESSION access without submitting the pending operation.
          return executeGraphQL<{ effectivePermissions: { __typename: string } }, Record<string, never>>(
            'query ConsoleAuthenticationCheck { effectivePermissions { __typename } }',
            { graphqlUrl: config.graphqlUrl, accessToken: token, locale, variables: {} },
          ).then((checked) => {
            if (getAuthSession() !== session) {
              return localFailure<TData>('insufficient_user_authentication', t('stepUpDescription'), {
                forbidden: false, stepUp,
              })
            }
            if (checked.unauthorized) {
              void requireReauthentication(undefined, {
                reason: 'unauthorized', requestId: checked.requestId, traceId: checked.traceId,
              })
            }
            if (checked.failure || checked.errors.length || !checked.data?.effectivePermissions) {
              return { ...checked, data: null } as GraphQLResult<TData>
            }
            void requireReauthentication(stepUp, { reason: 'step_up' })
            return localFailure<TData>(
              'insufficient_user_authentication',
              t('stepUpDescription'),
              { forbidden: false, stepUp, requiredScopes: decision.requiredScopes },
            )
          })
        }
      }

      return executeGraphQL<TData, TVariables>(document, {
        graphqlUrl: config.graphqlUrl,
        accessToken: token,
        locale,
        variables,
        operationName,
      }).then((result) => {
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
      })
    },
    [accessToken, config.graphqlUrl, locale, requireReauthentication, t],
  )
}
