import { hasManagementAccess } from '@identity/graphql-access'
import { queryOptions, useSuspenseQuery } from '@tanstack/react-query'
import { createFileRoute, redirect } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import type { ThemePreference } from '#/lib/appearance'
import { beginAuthorization } from '#/lib/authorization-flow'
import {
  accountAccessContext,
  GraphqlRequestError,
  identityGraphql,
} from '#/lib/graphql.server'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'
import { mfaUiState, storeTotpEnabled } from '#/lib/oauth.server'
import { consumeAccountFlash } from '#/lib/oauth-session.server'
import { loadConsoleUrl } from '#/lib/runtime-config.server'
import {
  type AccountData,
  type AccountSession,
  useAccount,
} from '#/modules/account/components/account-context'
import { resolveAccountLocale } from '#/modules/account/lib/account-locale'
import { ACCOUNT_QUERY_KEY } from '#/modules/account/lib/account-query'
import { AccountLayoutView } from '#/modules/account/pages/account-layout'

export type { AccountData, AccountSession }
export { useAccount }

const ACCOUNT_QUERY = `query AccountHome {
  account { id username email emailVerified givenName familyName nickname picture website birthdate zoneInfo locale theme createdAt }
  sessions(first: 50) { edges { node { id status current deviceName deviceType osName osVersion browserName browserVersion ipAddress lastActiveAt createdAt } } }
  security { mfaEnabled totpEnabled recoveryCodesRemaining preferredMfaMethod }
  passkeys { id name }
  effectivePermissions { requestableScopes effectiveScopes }
  accountEmailVerification { available pending { email changesEmail sentAt expiresAt resendAvailableAt } }
}`

const loadAccountData = createServerFn({ method: 'GET' }).handler(async () => {
  const browserLocale = requestLocale()
  try {
    const [data, mfa] = await Promise.all([
      identityGraphql<AccountData>(ACCOUNT_QUERY),
      mfaUiState(),
    ])
    if (data) await storeTotpEnabled(data.security.totpEnabled)
    const consoleUrl = hasManagementAccess(data?.effectivePermissions)
      ? await loadConsoleUrl()
      : undefined
    return {
      locale: resolveAccountLocale(data?.account.locale, browserLocale),
      theme: accountTheme(data?.account.theme),
      data,
      access: await accountAccessContext(data?.security.mfaEnabled),
      consoleUrl,
      mfa,
      error: undefined as string | undefined,
    }
  } catch (error) {
    return {
      locale: browserLocale,
      theme: 'system' as const,
      data: undefined,
      access: undefined,
      consoleUrl: undefined as string | undefined,
      mfa: { enrollment: undefined },
      error:
        error instanceof GraphqlRequestError
          ? error.message
          : error instanceof Error
            ? error.message
            : translate(browserLocale, 'temporaryError'),
    }
  }
})

/** One-shot flash messages stay outside the cache; they may be consumed once. */
const loadAccountFlash = createServerFn({ method: 'GET' }).handler(async () => ({
  flash: await consumeAccountFlash(),
}))

export const accountQuery = queryOptions({
  queryKey: ACCOUNT_QUERY_KEY,
  queryFn: () => loadAccountData(),
  // Fresh enough to skip a redundant read right after hydration. Account
  // actions invalidate this key, and the router invalidation that follows
  // lets the loader revalidate it.
  staleTime: 30_000,
})

export const Route = createFileRoute('/account')({
  loader: async ({ location, context }) => {
    const [page, { flash }] = await Promise.all([
      // The loader fills the request cache; the component reads the same key.
      context.queryClient.ensureQueryData(accountQuery),
      loadAccountFlash(),
    ])
    if (!page.data && !page.error) {
      // Authorization must reach the provider rather than the client route
      // tree, and come back to the page that needed it (for example after an
      // MFA change withdrew the previous account-center token).
      throw redirect({
        href: await beginAuthorization({ data: { returnTo: location.href } }),
        reloadDocument: true,
      })
    }
    return { page, flash }
  },
  headers: () => ({ 'Cache-Control': 'private, no-store' }),
  component: AccountLayout,
})

function AccountLayout() {
  const { flash } = Route.useLoaderData()
  const { data: current } = useSuspenseQuery(accountQuery)
  return <AccountLayoutView current={current} flash={flash} />
}

function accountTheme(value: string | undefined): ThemePreference {
  return value === 'light' || value === 'dark' ? value : 'system'
}
