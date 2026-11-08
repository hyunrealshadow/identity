import {
  accessToken,
  clearAuthorizationCookie,
  elevatedAccessToken,
} from './oauth.server'
import { forwardRequestContext } from './request-context.server'
import { backchannelIdentityGraphqlUrl } from './identity-url.server'
import { emitEvent, fetchWithSpan } from './observability.server'
import { preflightOperation, type PreflightContext, type PreflightResult } from '@identity/graphql-access'
import { translate } from './i18n'
import { requestLocale } from './i18n.server'

export interface GraphqlError {
  message: string
  extensions?: {
    kind?: string
    code?: string | number
    requiredScope?: string
    requiredScopes?: string[]
    acr_values?: string
    max_age?: number
    fields?: Array<{ field: string; code: number; message: string }>
  }
}

export class GraphqlRequestError extends Error {
  readonly errors: Array<GraphqlError>
  readonly challenge?: StepUpChallenge

  constructor(errors: Array<GraphqlError>, challenge?: StepUpChallenge) {
    super(errors[0]?.message ?? 'GraphQL request failed')
    this.name = 'GraphqlRequestError'
    this.errors = errors
    this.challenge = challenge
  }
}

/** No usable account credential remains; recovery must use ordinary sign-in. */
export class AccountSessionExpiredError extends Error {
  constructor() {
    super(translate(requestLocale(), 'accountAuthenticationRequired'))
    this.name = 'AccountSessionExpiredError'
  }
}

export interface StepUpChallenge {
  acrValues?: string
  maxAge?: number
}

interface GraphqlOptions { authorization?: 'default' | 'elevated' }

async function graphqlAccessToken(options?: GraphqlOptions) {
  return options?.authorization === 'elevated'
    ? ((await elevatedAccessToken()) ?? (await accessToken()))
    : await accessToken()
}

/** Check the selected API before opening a form, without submitting it. */
export async function preflightIdentityGraphql(
  query: string,
  variables?: Record<string, unknown>,
  options?: GraphqlOptions,
) {
  const standard = await accessToken()
  const elevated =
    options?.authorization === 'elevated' ? await elevatedAccessToken() : undefined
  if (!standard && !elevated) throw new AccountSessionExpiredError()

  let result = await evaluatePreflight(query, variables, elevated ?? standard ?? '')
  // An elevation token is minted for a single purpose. After an MFA change it
  // can carry `account.*` only, so an unrelated operation's scope looks
  // forbidden even though reauthenticating for that purpose would grant it.
  // The ordinary token still answers whether the operation is reachable that
  // way, so let it run the same check instead of reporting a dead end.
  if (result?.status === 'forbidden' && elevated && standard) {
    const fallback = await evaluatePreflight(query, variables, standard)
    if (fallback && fallback.status !== 'forbidden') result = fallback
  }
  if (result) assertPreflightRejection(result)
}

export async function identityGraphql<T>(
  query: string,
  variables?: Record<string, unknown>,
  options?: GraphqlOptions,
) {
  const token = await graphqlAccessToken(options)
  if (!token) return
  const preflight = await evaluatePreflight(query, variables, token)
  if (preflight) assertPreflightRejection(preflight)
  const headers = forwardRequestContext(
    new Headers({
      accept: 'application/graphql-response+json, application/json',
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
    }),
  )
  const response = await fetchWithSpan(
    new URL('/graphql', backchannelIdentityGraphqlUrl()),
    {
      method: 'POST',
      headers,
      body: JSON.stringify({ query, variables }),
    },
  )
  const payload = (await response.json()) as {
    data?: T
    errors?: Array<GraphqlError>
  }
  if (response.status === 401) {
    const challenge = parseStepUpChallenge(
      response.headers.get('www-authenticate'),
    )
    if (challenge) {
      throw new GraphqlRequestError(
        payload.errors ?? [{ message: 'Step-up authentication is required' }],
        challenge,
      )
    }
    await clearAuthorizationCookie()
    return
  }
  if (!response.ok || payload.errors?.length) {
    throw new GraphqlRequestError(
      payload.errors ?? [{ message: `GraphQL request failed (${response.status})` }],
    )
  }
  return payload.data
}

function tokenPreflightContext(token: string): PreflightContext | undefined {
  let claims: Record<string, unknown>
  try {
    claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'))
  } catch {
    // Opaque tokens have no locally readable requirements context.
    return
  }
  if (claims === null || typeof claims !== 'object' || Array.isArray(claims)) return
  if (typeof claims.scope !== 'string') return
  return {
    scopes: claims.scope.split(/\s+/).filter(Boolean),
    acr: typeof claims.acr === 'string' ? claims.acr : undefined,
    authTime: typeof claims.auth_time === 'number' ? claims.auth_time : undefined,
    user: true,
  }
}

/** Serialize only the context used by the same server preflight. */
export async function accountAccessContext(mfaEnabled?: boolean) {
  const standard = await graphqlAccessToken()
  const elevated = await graphqlAccessToken({ authorization: 'elevated' })
  const context = (token?: string) => {
    const parsed = token ? tokenPreflightContext(token) : undefined
    return parsed ? { ...parsed, mfaEnabled } : undefined
  }
  return { default: context(standard), elevated: context(elevated) }
}

/** Local checks never replace live authorization or submit the pending write. */
async function evaluatePreflight(
  query: string,
  variables: Record<string, unknown> | undefined,
  token: string,
): Promise<PreflightResult | undefined> {
  const context = tokenPreflightContext(token)
  if (!context) return
  let result = preflightOperation(query, variables, context)
  if (result.status === 'unknown' && context.scopes.includes('account.read')) {
    const withoutMfa = preflightOperation(query, variables, { ...context, mfaEnabled: false })
    const withMfa = preflightOperation(query, variables, { ...context, mfaEnabled: true })
    if (JSON.stringify(withoutMfa) !== JSON.stringify(withMfa)) {
      // Resolve the account-dependent requirement with a read-only query and
      // the same authorization that will be used for the pending operation.
      const headers = forwardRequestContext(new Headers({
        accept: 'application/graphql-response+json, application/json',
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      }))
      try {
        const response = await fetchWithSpan(new URL('/graphql', backchannelIdentityGraphqlUrl()), {
          method: 'POST', headers,
          body: JSON.stringify({ query: 'query AccessPreflightFactors { security { mfaEnabled } }' }),
        })
        const payload = await response.json() as { data?: { security?: { mfaEnabled?: boolean } } }
        if (response.ok && typeof payload?.data?.security?.mfaEnabled === 'boolean') {
          result = preflightOperation(query, variables, { ...context, mfaEnabled: payload.data.security.mfaEnabled })
        }
      } catch {
        // Unavailable advisory state leaves the authoritative API check intact.
        emitEvent('graphql.access_preflight', { outcome: 'unresolved', reason: 'factor_context_unavailable' })
      }
    }
  }
  return result
}

function assertPreflightRejection(result: PreflightResult) {
  if (result.status !== 'forbidden' && result.status !== 'reauthentication') return
  const authentication = result.status === 'reauthentication'
  emitEvent('graphql.access_preflight', {
    outcome: 'rejected', reason: result.status,
    attributes: { 'graphql.preflight': true },
  })
  const message = translate(requestLocale(), authentication ? 'accountAuthenticationRequired' : 'accountPermissionRequired')
  const challenge = authentication ? { acrValues: result.acrValues, maxAge: result.maxAge } : undefined
  throw new GraphqlRequestError([{
    message,
    extensions: {
      kind: 'authorization_error',
      code: authentication ? 'insufficient_user_authentication' : 'insufficient_scope',
      requiredScopes: result.requiredScopes,
      acr_values: result.acrValues,
      max_age: result.maxAge,
    },
  }], challenge)
}

export function parseStepUpChallenge(
  value: string | null,
): StepUpChallenge | undefined {
  if (!value?.startsWith('Bearer ')) return
  const error = quotedParameter(value, 'error')
  if (error !== 'insufficient_user_authentication') return
  const maxAgeValue = quotedParameter(value, 'max_age')
  const maxAge = maxAgeValue === undefined ? undefined : Number(maxAgeValue)
  return {
    acrValues: quotedParameter(value, 'acr_values'),
    maxAge:
      maxAge !== undefined && Number.isInteger(maxAge) && maxAge >= 0
        ? maxAge
        : undefined,
  }
}

function quotedParameter(value: string, name: string) {
  const match = value.match(new RegExp(`(?:^|[,\\s])${name}="([^"]*)"`))
  return match?.[1]
}
