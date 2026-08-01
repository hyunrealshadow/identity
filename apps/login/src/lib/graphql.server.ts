import {
  accessToken,
  clearAuthorizationCookie,
  elevatedAccessToken,
} from './oauth.server'
import { requestLocale } from './i18n.server'

const API_URL = process.env.IDENTITY_API_URL ?? 'https://localhost:5150'

export interface GraphqlError {
  message: string
  extensions?: {
    kind?: string
    code?: string | number
    requiredScope?: string
    fields?: Array<{ field: string; code: number; message: string }>
  }
}

export class GraphqlRequestError extends Error {
  readonly errors: Array<GraphqlError>

  constructor(errors: Array<GraphqlError>) {
    super(errors[0]?.message ?? 'GraphQL request failed')
    this.name = 'GraphqlRequestError'
    this.errors = errors
  }
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
  const response = await fetch(new URL('/graphql', API_URL), {
    method: 'POST',
    headers: {
      accept: 'application/graphql-response+json, application/json',
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'accept-language': requestLocale(),
    },
    body: JSON.stringify({ query, variables }),
  })
  if (response.status === 401) {
    await clearAuthorizationCookie()
    return
  }
  const payload = (await response.json()) as {
    data?: T
    errors?: Array<GraphqlError>
  }
  if (!response.ok || payload.errors?.length) {
    throw new GraphqlRequestError(
      payload.errors ?? [{ message: `GraphQL request failed (${response.status})` }],
    )
  }
  return payload.data
}
