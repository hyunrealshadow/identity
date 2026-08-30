import {
  accessToken,
  clearAuthorizationCookie,
  elevatedAccessToken,
} from './oauth.server'
import { forwardRequestContext } from './request-context.server'
import { backchannelIdentityGraphqlUrl } from './identity-url.server'

export interface GraphqlError {
  message: string
  extensions?: {
    kind?: string
    code?: string | number
    requiredScope?: string
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

export interface StepUpChallenge {
  acrValues?: string
  maxAge?: number
}

export async function identityGraphql<T>(
  query: string,
  variables?: Record<string, unknown>,
  options?: { authorization?: 'default' | 'elevated' },
) {
  const token =
    options?.authorization === 'elevated'
      ? ((await elevatedAccessToken()) ?? (await accessToken()))
      : await accessToken()
  if (!token) return
  const headers = forwardRequestContext(
    new Headers({
      accept: 'application/graphql-response+json, application/json',
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
    }),
  )
  const response = await fetch(
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
