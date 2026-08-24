import { Alert } from '@heroui/react'
import { Link, Outlet, createFileRoute, redirect } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { AtSign, KeyRound, Laptop, UserRound, X } from 'lucide-react'
import { useEffect, useState } from 'react'

import { AccountAvatar } from '#/components/account-avatar'
import { UserMenu } from '#/components/user-menu'
import { resolveAccountLocale } from '#/lib/account-locale'
import { beginAuthorization } from '#/lib/authorization-flow'
import { GraphqlRequestError, identityGraphql } from '#/lib/graphql.server'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'
import { mfaUiState } from '#/lib/oauth.server'
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
  viewer: {
    account: { id: string; username: string; email: string; emailVerified: boolean; givenName?: string; familyName?: string; nickname?: string; picture?: string; website?: string; birthdate?: string; locale?: string; theme?: string; createdAt: string }
    sessions: { edges: Array<{ node: AccountSession }> }
    security: { totpEnabled: boolean; recoveryCodesRemaining: number }
  }
}

const ACCOUNT_QUERY = `query AccountHome {
  viewer {
    account { id username email emailVerified givenName familyName nickname picture website birthdate locale theme createdAt }
    sessions(first: 50) { edges { node { id status current deviceName deviceType osName osVersion browserName browserVersion ipAddress lastActiveAt createdAt } } }
    security { totpEnabled recoveryCodesRemaining }
  }
}`

const loadAccount = createServerFn({ method: 'GET' }).handler(async () => {
  const browserLocale = requestLocale()
  const flash = await consumeAccountFlash()
  try {
    const [data, mfa] = await Promise.all([identityGraphql<AccountData>(ACCOUNT_QUERY), mfaUiState()])
    return {
      locale: resolveAccountLocale(
        data?.viewer.account.locale,
        browserLocale,
      ),
      theme: accountTheme(data?.viewer.account.theme),
      data,
      mfa,
      flash,
      error: undefined,
    }
  } catch (error) {
    return {
      locale: browserLocale,
      theme: 'system' as const,
      data: undefined,
      mfa: { enrollment: undefined },
      flash,
      error: error instanceof GraphqlRequestError ? error.message : error instanceof Error ? error.message : translate(browserLocale, 'temporaryError'),
    }
  }
})

export function useAccount() {
  const page = Route.useLoaderData()
  if (!page.data) throw new Error(page.error ?? 'Account data is unavailable')
  return { ...page, data: page.data }
}

export const Route = createFileRoute('/account')({
  loader: async () => {
    const page = await loadAccount()
    if (!page.data && !page.error) throw redirect({ href: await beginAuthorization() })
    return page
  },
  component: AccountLayout,
})

function AccountLayout() {
  const page = Route.useLoaderData()
  const [visibleMessage, setVisibleMessage] = useState(page.flash.message)
  const [visibleError, setVisibleError] = useState(page.flash.error)

  useEffect(() => {
    applyTheme(page.theme)
    document.documentElement.dataset.themePreference = page.theme
    if (page.theme !== 'system') return
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const followSystem = () => applyTheme('system')
    media.addEventListener('change', followSystem)
    return () => media.removeEventListener('change', followSystem)
  }, [page.theme])

  useEffect(() => {
    setVisibleMessage(page.flash.message)
    setVisibleError(page.flash.error)
    if (!page.flash.message) return

    const timeout = window.setTimeout(() => setVisibleMessage(undefined), 4000)
    return () => window.clearTimeout(timeout)
  }, [page.flash])

  if (!page.data) {
    return <main className="flex min-h-screen items-center justify-center p-6"><Alert status="danger" className="max-w-lg"><Alert.Indicator /><Alert.Content><Alert.Title>{translate(page.locale, 'unableToContinue')}</Alert.Title><Alert.Description>{page.error}</Alert.Description></Alert.Content></Alert></main>
  }

  const account = page.data.viewer.account
  const displayName = [account.givenName, account.familyName].filter(Boolean).join(' ') || account.nickname || account.username
  const t = (key: Parameters<typeof translate>[1]) => translate(page.locale, key)
  const navItems = [
    { to: '/account/profile' as const, label: t('accountProfile'), icon: UserRound },
    { to: '/account/identifiers' as const, label: t('accountIdentifiers'), icon: AtSign },
    { to: '/account/security' as const, label: t('accountSecurity'), icon: KeyRound },
    { to: '/account/sessions' as const, label: t('accountSessions'), icon: Laptop },
  ]

  return (
    <main lang={page.locale} className="min-h-screen bg-background">
        <header className="account-topbar border-b border-separator">
          <div className="mx-auto flex h-14 max-w-5xl items-center justify-between px-5">
            <Link to="/account/profile" preload={false} className="text-sm font-semibold tracking-tight">Identity</Link>
            <div className="flex items-center">
              <span className="js-only">
                <UserMenu
                  user={{ name: displayName, email: account.email, picture: account.picture }}
                  menuLabel={t('accountMenuLabel')}
                  manageLabel={t('accountMenuManage')}
                  signOutLabel={t('accountSignOut')}
                  requestFailedLabel={t('accountRequestFailed')}
                />
              </span>
            </div>
          </div>
        </header>
        <div className="mx-auto grid max-w-5xl gap-8 px-5 py-8 md:grid-cols-[180px_minmax(0,1fr)]">
          <aside>
            <div className="mb-5 flex items-center gap-3 px-2">
              <AccountAvatar name={displayName} picture={account.picture} size="md" className="shrink-0" />
              <div className="min-w-0"><p className="truncate text-sm font-medium">{displayName}</p><p className="truncate text-xs text-muted">{account.email}</p></div>
            </div>
            <nav className="account-nav flex gap-1 overflow-x-auto md:flex-col" aria-label={t('accountSettings')}>
              {navItems.map(({ to, label, icon: Icon }) => {
                return <Link key={to} to={to} preload={false} activeOptions={{ exact: true }} activeProps={{ className: 'font-medium' }} inactiveProps={{ className: 'text-muted' }} className="account-nav-link flex min-w-fit items-center gap-2.5 rounded-field px-3 py-2 text-sm"><Icon className="size-4" aria-hidden="true" />{label}</Link>
              })}
            </nav>
          </aside>
          <section className="min-w-0">
            <div className="mb-5 space-y-3">
              {visibleMessage ? <Alert status="success"><Alert.Indicator /><Alert.Content><Alert.Title>{visibleMessage === 'reauthenticated' ? t('accountReauthenticated') : t('accountSaved')}</Alert.Title></Alert.Content><button type="button" className="ml-auto cursor-pointer rounded-sm p-1 text-muted hover:bg-surface-secondary hover:text-foreground" aria-label={t('close')} onClick={() => setVisibleMessage(undefined)}><X className="size-4" aria-hidden="true" /></button></Alert> : null}
              {visibleError ? <Alert status="danger"><Alert.Indicator /><Alert.Content><Alert.Title>{t('accountRequestFailed')}</Alert.Title><Alert.Description>{visibleError}</Alert.Description></Alert.Content><button type="button" className="ml-auto cursor-pointer rounded-sm p-1 text-muted hover:bg-surface-secondary hover:text-foreground" aria-label={t('close')} onClick={() => setVisibleError(undefined)}><X className="size-4" aria-hidden="true" /></button></Alert> : null}
            </div>
            <Outlet />
          </section>
        </div>
    </main>
  )
}

function accountTheme(value: string | undefined): ThemePreference {
  return value === 'light' || value === 'dark' ? value : 'system'
}
