import { GraphqlRequestError, identityGraphql } from '#/lib/graphql.server'
import type { AccountSessionConnection } from '#/modules/account/components/account-context'

export const ACCOUNT_SESSIONS_PAGE_SIZE = 20

export interface AccountSessionsSearch {
  after?: string
  before?: string
}

const ACCOUNT_SESSIONS_QUERY = `query AccountSessions($first: Int, $after: String, $last: Int, $before: String) {
  sessions(first: $first, after: $after, last: $last, before: $before) {
    pageInfo {
      hasPreviousPage
      hasNextPage
      startCursor
      endCursor
    }
    edges {
      cursor
      node {
        id
        status
        current
        deviceName
        deviceType
        osName
        osVersion
        browserName
        browserVersion
        ipAddress
        lastActiveAt
        createdAt
      }
    }
  }
}`

interface AccountSessionsResult {
  sessions: AccountSessionConnection
}

export async function fetchAccountSessions(
  input: AccountSessionsSearch,
): Promise<AccountSessionConnection | undefined> {
  const variables = input.before
    ? { last: ACCOUNT_SESSIONS_PAGE_SIZE, before: input.before }
    : { first: ACCOUNT_SESSIONS_PAGE_SIZE, after: input.after }
  try {
    const result = await identityGraphql<AccountSessionsResult>(
      ACCOUNT_SESSIONS_QUERY,
      variables,
    )
    return result?.sessions
  } catch (error) {
    if (error instanceof GraphqlRequestError) return undefined
    throw error
  }
}
