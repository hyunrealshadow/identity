import { useContext, useMemo } from 'react'

import { useAuth } from '#/lib/auth/context'
import { useLocale } from '#/lib/i18n'
import { useRuntimeConfig } from '#/lib/runtime-config'
import { RequestableAccessContext } from './access-context'
import { createGraphQLRequester, type GraphQLRequester } from './requester'

/** @deprecated Prefer `GraphQLRequester`; kept for existing imports. */
export type GraphQLRequest = GraphQLRequester

/**
 * The single request entry point. Preflight, step-up recovery, unauthorized
 * handling and request correlation live in `createGraphQLRequester` so the
 * same path serves TanStack Query functions and imperative callers.
 */
export function useGraphQL(): GraphQLRequester {
  const config = useRuntimeConfig()
  const requestable = useContext(RequestableAccessContext)
  const { locale, t } = useLocale()
  const { accessToken, requireReauthentication } = useAuth()

  return useMemo(
    () =>
      createGraphQLRequester({
        graphqlUrl: config.graphqlUrl,
        locale,
        accessToken,
        requireReauthentication,
        requestable,
        messages: {
          forbidden: t('forbiddenDescription'),
          stepUp: t('stepUpDescription'),
        },
      }),
    [
      accessToken,
      config.graphqlUrl,
      locale,
      requestable,
      requireReauthentication,
      t,
    ],
  )
}
