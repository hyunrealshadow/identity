import { Alert, AlertAction, AlertDescription, AlertTitle } from '@identity/ui/components/alert'
import { Button } from '@identity/ui/components/button'
import { queryOptions, useSuspenseQuery } from '@tanstack/react-query'
import { Link, Outlet, createFileRoute, redirect } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { AtSign, CircleAlert, CircleCheck, KeyRound, Laptop, UserRound, X } from 'lucide-react'
import { useEffect, useState } from 'react'

import { AccountReauthProvider } from '#/components/reauthentication-popup'
import { UserMenu } from '#/components/user-menu'
import { resolveAccountLocale } from '#/lib/account-locale'
import { ACCOUNT_QUERY_KEY } from '#/lib/account-query'
import { beginAuthorization } from '#/lib/authorization-flow'
import { GraphqlRequestError, identityGraphql, accountAccessContext } from '#/lib/graphql.server'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'
import { mfaUiState, storeTotpEnabled } from '#/lib/oauth.server'
import { consumeAccountFlash } from '#/lib/oauth-session.server'
import { applyTheme, type ThemePreference } from '#/lib/appearance'

export interface AccountSession {
  id: string
  status: string
  current: boolean
  deviceName?: string
  deviceType?: string
  osName?: string
  osVersion?: string
  browserName?: string
  browserVersion?: string
  ipAddress?: string
  lastActiveAt?: string
  createdAt: string
}

export interface AccountData {
  passkeys: Array<{ id: string; name: string }>
  account: { id: string; username: string; email: string; emailVerified: boolean; givenName?: string; familyName?: string; nickname?: string; picture?: string; website?: string; birthdate?: string; zoneInfo?: string; locale?: string; theme?: string; createdAt: string }
  sessions: { edges: Array<{ node: AccountSession }> }
  security: { mfaEnabled: boolean; totpEnabled: boolean; recoveryCodesRemaining: number; preferredMfaMethod: 'passkey' | 'otp' }
}

const ACCOUNT_QUERY = `query AccountHome {
  account { id username email emailVerified givenName familyName nickname picture website birthdate zoneInfo locale theme createdAt }
  sessions(first: 50) { edges { node { id status current deviceName deviceType osName osVersion browserName browserVersion ipAddress lastActiveAt createdAt } } }
  security { mfaEnabled totpEnabled recoveryCodesRemaining preferredMfaMethod }
  passkeys { id name }
}`

const loadAccountData = createServerFn({ method: 'GET' }).handler(async () => {
  const browserLocale = requestLocale()
  try {
    const [data, mfa] = await Promise.all([identityGraphql<AccountData>(ACCOUNT_QUERY), mfaUiState()])
    if (data) await storeTotpEnabled(data.security.totpEnabled)
    return {
      locale: resolveAccountLocale(
        data?.account.locale,
        browserLocale,
      ),
      theme: accountTheme(data?.account.theme),
      data,
      access: await accountAccessContext(data?.security.mfaEnabled),
      mfa,
      error: undefined as string | undefined,
    }
  } catch (error) {
    return {
      locale: browserLocale,
      theme: 'system' as const,
      data: undefined,
      access: undefined,
      mfa: { enrollment: undefined },
      error: error instanceof GraphqlRequestError ? error.message : error instanceof Error ? error.message : translate(browserLocale, 'temporaryError'),
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

export function useAccount() {
  const { flash } = Route.useLoaderData()
  const { data: page } = useSuspenseQuery(accountQuery)
  if (!page.data) throw new Error(page.error ?? 'Account data is unavailable')
  return { ...page, flash, data: page.data }
}

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
  const [visibleMessage, setVisibleMessage] = useState(flash.message)
  const [visibleError, setVisibleError] = useState(flash.error)

  useEffect(() => {
    applyTheme(current.theme)
    document.documentElement.dataset.themePreference = current.theme
    if (current.theme !== 'system') return
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const followSystem = () => applyTheme('system')
    media.addEventListener('change', followSystem)
    return () => media.removeEventListener('change', followSystem)
  }, [current.theme])

  useEffect(() => {
    setVisibleMessage(flash.message)
    setVisibleError(flash.error)
    if (!flash.message) return

    const timeout = window.setTimeout(() => setVisibleMessage(undefined), 4000)
    return () => window.clearTimeout(timeout)
  }, [flash])

  if (!current.data) {
    if (!current.error) {
      // Missing data without an error means the account-center token was just
      // withdrawn — an MFA change does that — and the loader is restarting
      // authorization for this same page. Rendering the failure panel here
      // would flash a dead end the user cannot act on.
      return <main className="min-h-screen bg-background" aria-busy="true" />
    }
    return <main className="flex min-h-screen items-center justify-center p-6"><Alert variant="destructive" className="max-w-lg"><CircleAlert aria-hidden="true" /><AlertTitle>{translate(current.locale, 'unableToContinue')}</AlertTitle><AlertDescription>{current.error}</AlertDescription></Alert></main>
  }

  const account = current.data.account
  const displayName = [account.givenName, account.familyName].filter(Boolean).join(' ') || account.nickname || account.username
  const t = (key: Parameters<typeof translate>[1]) => translate(current.locale, key)
  const navItems = [
    { to: '/account/profile' as const, label: t('accountProfile'), icon: UserRound },
    { to: '/account/identifiers' as const, label: t('accountIdentifiers'), icon: AtSign },
    { to: '/account/security' as const, label: t('accountSecurity'), icon: KeyRound },
    { to: '/account/sessions' as const, label: t('accountSessions'), icon: Laptop },
  ]

  return (
    <main lang={current.locale} className="min-h-screen bg-background">
        <header className="account-topbar border-b border-border">
          <div className="mx-auto flex h-14 max-w-5xl items-center justify-between px-5">
            <Link to="/account/profile" preload={false} className="text-sm font-semibold tracking-tight">Identity</Link>
            <div className="flex items-center">
              <span className="js-only">
                <UserMenu
                  user={{ name: displayName, email: account.email, picture: account.picture }}
                  menuLabel={t('accountMenuLabel')}
                  signOutLabel={t('accountSignOut')}
                  switchAccountLabel={t('switchAccount')}
                  requestFailedLabel={t('accountRequestFailed')}
                />
              </span>
            </div>
          </div>
        </header>
        <div className="mx-auto grid max-w-5xl gap-8 px-5 py-8 md:grid-cols-[180px_minmax(0,1fr)]">
          <aside>
            <nav className="account-nav grid grid-cols-2 gap-1 md:flex md:flex-col" aria-label={t('accountSettings')}>
              {navItems.map(({ to, label, icon: Icon }) => {
                return <Link key={to} to={to} preload={false} activeOptions={{ exact: true }} activeProps={{ className: 'font-medium' }} inactiveProps={{ className: 'text-muted-foreground' }} className="account-nav-link flex min-w-fit items-center gap-2.5 rounded-md px-3 py-2 text-sm"><Icon className="size-4" aria-hidden="true" />{label}</Link>
              })}
            </nav>
          </aside>
          <section className="min-w-0">
            <AccountReauthProvider locale={current.locale} access={current.access}>
            <div className="mb-5 space-y-3">
              {visibleMessage ? <Alert className="text-success"><CircleCheck aria-hidden="true" /><AlertTitle>{visibleMessage === 'reauthenticated' ? t('accountReauthenticated') : t('accountSaved')}</AlertTitle><AlertAction><Button variant="ghost" size="icon-xs" aria-label={t('close')} onClick={() => setVisibleMessage(undefined)}><X aria-hidden="true" /></Button></AlertAction></Alert> : null}
              {visibleError ? <Alert variant="destructive"><CircleAlert aria-hidden="true" /><AlertTitle>{t('accountRequestFailed')}</AlertTitle><AlertDescription>{visibleError}</AlertDescription><AlertAction><Button variant="ghost" size="icon-xs" aria-label={t('close')} onClick={() => setVisibleError(undefined)}><X aria-hidden="true" /></Button></AlertAction></Alert> : null}
            </div>
            <Outlet />
            </AccountReauthProvider>
          </section>
        </div>
    </main>
  )
}

function accountTheme(value: string | undefined): ThemePreference {
  return value === 'light' || value === 'dark' ? value : 'system'
}
