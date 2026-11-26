import { Alert, AlertAction, AlertDescription, AlertTitle } from '@identity/ui/components/alert'
import { Button } from '@identity/ui/components/button'
import { Link, Outlet } from '@tanstack/react-router'
import { AtSign, CircleAlert, CircleCheck, KeyRound, Laptop, UserRound, X } from 'lucide-react'
import { useEffect, useState } from 'react'

import { applyTheme, type ThemePreference } from '#/lib/appearance'
import { translate, type Locale } from '#/lib/i18n'
import {
  AccountProvider,
  type AccountData,
  type AccountFlash,
  type AccountMfaUiState,
} from '#/modules/account/components/account-context'
import { AccountReauthProvider } from '#/modules/account/components/reauthentication-popup'
import { UserMenu } from '#/modules/account/components/user-menu'
import type { AccountAccessContext } from '#/modules/account/lib/account-operations'

export interface AccountPageState {
  locale: Locale
  theme: ThemePreference
  data?: AccountData
  access?: AccountAccessContext
  consoleUrl?: string
  mfa: AccountMfaUiState
  error?: string
}

export function AccountLayoutView({
  current,
  flash,
}: {
  current: AccountPageState
  flash: AccountFlash
}) {
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
    return (
      <main className="flex min-h-screen items-center justify-center p-6">
        <Alert variant="destructive" className="max-w-lg">
          <CircleAlert aria-hidden="true" />
          <AlertTitle>{translate(current.locale, 'unableToContinue')}</AlertTitle>
          <AlertDescription>{current.error}</AlertDescription>
        </Alert>
      </main>
    )
  }

  const account = current.data.account
  const displayName =
    [account.givenName, account.familyName].filter(Boolean).join(' ') ||
    account.nickname ||
    account.username
  const t = (key: Parameters<typeof translate>[1]) =>
    translate(current.locale, key)
  const navItems = [
    {
      to: '/account/profile' as const,
      label: t('accountProfile'),
      icon: UserRound,
    },
    {
      to: '/account/identifiers' as const,
      label: t('accountIdentifiers'),
      icon: AtSign,
    },
    {
      to: '/account/security' as const,
      label: t('accountSecurity'),
      icon: KeyRound,
    },
    {
      to: '/account/sessions' as const,
      label: t('accountSessions'),
      icon: Laptop,
    },
  ]

  return (
    <AccountProvider
      value={{
        locale: current.locale,
        theme: current.theme,
        data: current.data,
        access: current.access,
        consoleUrl: current.consoleUrl,
        mfa: current.mfa,
        flash,
      }}
    >
      <main lang={current.locale} className="min-h-screen bg-background">
        <header className="account-topbar border-b border-border">
          <div className="mx-auto flex h-14 max-w-5xl items-center justify-between px-5">
            <Link
              to="/account/profile"
              preload={false}
              className="text-sm font-semibold tracking-tight"
            >
              Identity
            </Link>
            <div className="flex items-center">
              <span className="js-only">
                <UserMenu
                  user={{
                    name: displayName,
                    email: account.email,
                    picture: account.picture,
                  }}
                  menuLabel={t('accountMenuLabel')}
                  consoleUrl={current.consoleUrl}
                  consoleLabel={t('consoleLabel')}
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
            <nav
              className="account-nav grid grid-cols-2 gap-1 md:flex md:flex-col"
              aria-label={t('accountSettings')}
            >
              {navItems.map(({ to, label, icon: Icon }) => {
                return (
                  <Link
                    key={to}
                    to={to}
                    preload={false}
                    activeOptions={{ exact: true }}
                    activeProps={{ className: 'font-medium' }}
                    inactiveProps={{ className: 'text-muted-foreground' }}
                    className="account-nav-link flex min-w-fit items-center gap-2.5 rounded-md px-3 py-2 text-sm"
                  >
                    <Icon className="size-4" aria-hidden="true" />
                    {label}
                  </Link>
                )
              })}
            </nav>
          </aside>
          <section className="min-w-0">
            <AccountReauthProvider
              locale={current.locale}
              access={current.access}
            >
              <div className="mb-5 space-y-3">
                {visibleMessage ? (
                  <Alert className="text-success">
                    <CircleCheck aria-hidden="true" />
                    <AlertTitle>
                      {visibleMessage === 'reauthenticated'
                        ? t('accountReauthenticated')
                        : visibleMessage === 'verificationSent'
                          ? t('accountVerificationEmailSent')
                          : t('accountSaved')}
                    </AlertTitle>
                    <AlertAction>
                      <Button
                        variant="ghost"
                        size="icon-xs"
                        aria-label={t('close')}
                        onClick={() => setVisibleMessage(undefined)}
                      >
                        <X aria-hidden="true" />
                      </Button>
                    </AlertAction>
                  </Alert>
                ) : null}
                {visibleError ? (
                  <Alert variant="destructive">
                    <CircleAlert aria-hidden="true" />
                    <AlertTitle>{t('accountRequestFailed')}</AlertTitle>
                    <AlertDescription>{visibleError}</AlertDescription>
                    <AlertAction>
                      <Button
                        variant="ghost"
                        size="icon-xs"
                        aria-label={t('close')}
                        onClick={() => setVisibleError(undefined)}
                      >
                        <X aria-hidden="true" />
                      </Button>
                    </AlertAction>
                  </Alert>
                ) : null}
              </div>
              <Outlet />
            </AccountReauthProvider>
          </section>
        </div>
      </main>
    </AccountProvider>
  )
}
