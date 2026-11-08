import { Button } from '@identity/ui/components/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@identity/ui/components/dropdown-menu'
import { Toaster } from '@identity/ui/components/sonner'
import { Outlet, useNavigate } from '@tanstack/react-router'
import { ArrowLeftRight, ChevronDown, ExternalLink, LogOut } from 'lucide-react'
import { useEffect, useState } from 'react'

import {
  Brand,
  MobileNavigation,
  NavigationLinks,
  SidebarCollapseButton,
} from '#/components/app-navigation'
import { AccountAvatar } from '#/components/account-avatar'
import { useAuth } from '#/lib/auth/context'
import { currentReturnTo } from '#/lib/auth/return-to'
import type { IdTokenClaims } from '#/lib/auth/session'
import { useTranslator } from '#/lib/i18n'
import { useRuntimeConfig } from '#/lib/runtime-config'

import {
  AppBreadcrumbs,
  BreadcrumbProvider,
  usePageBreadcrumbs,
} from '#/components/app-breadcrumbs'

const SIDEBAR_STORAGE_KEY = 'identity.console.sidebar.collapsed'

function readCollapsed(): boolean {
  try {
    return window.localStorage.getItem(SIDEBAR_STORAGE_KEY) === '1'
  } catch {
    return false
  }
}

function displayName(
  claims: IdTokenClaims | undefined,
  unknown: string,
): string {
  const full = [claims?.given_name, claims?.family_name]
    .filter(Boolean)
    .join(' ')
    .trim()
  return (
    full ||
    claims?.nickname ||
    claims?.preferred_username ||
    claims?.name ||
    unknown
  )
}

function emailOf(claims: IdTokenClaims | undefined): string {
  return claims?.email ?? ''
}

function AccountMenu({
  name,
  email,
  picture,
  accountUrl,
  onSwitchAccount,
  onSignOut,
}: {
  name: string
  email: string
  picture?: string | null
  accountUrl: string
  onSwitchAccount: () => void
  onSignOut: () => void
}) {
  const t = useTranslator()
  const label = t('accountMenuFor', { name })
  const avatarLabel = t('accountAvatarLabel', { name })

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button
            variant="ghost"
            size="sm"
            aria-label={label}
            className="h-10 max-w-64 gap-2 px-1.5"
          />
        }
      >
        <AccountAvatar
          name={name}
          picture={picture}
          label={avatarLabel}
          size="sm"
        />
        <span className="hidden min-w-0 text-start sm:block">
          <span className="block truncate text-sm font-medium">{name}</span>
          <span className="block truncate text-xs font-normal text-muted-foreground">
            {email}
          </span>
        </span>
        <ChevronDown
          className="hidden size-3.5 text-muted-foreground sm:block"
          aria-hidden="true"
        />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-56">
        <DropdownMenuItem render={<a href={accountUrl} />}>
          <ExternalLink className="text-muted-foreground" aria-hidden="true" />
          {t('accountCenter')}
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={onSwitchAccount}>
          <ArrowLeftRight className="text-muted-foreground" aria-hidden="true" />
          {t('switchAccount')}
        </DropdownMenuItem>
        <DropdownMenuItem variant="destructive" onClick={onSignOut}>
          <LogOut aria-hidden="true" />
          {t('signOut')}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export function AppShell() {
  return (
    <BreadcrumbProvider>
      <AppShellLayout />
    </BreadcrumbProvider>
  )
}

function AppShellLayout() {
  const t = useTranslator()
  const config = useRuntimeConfig()
  const { claims, signIn, logoutSso } = useAuth()
  const navigate = useNavigate()
  const [collapsed, setCollapsed] = useState(readCollapsed)

  const name = displayName(claims, t('unknown'))
  const email = emailOf(claims)
  const picture = claims?.picture
  const breadcrumbs = usePageBreadcrumbs()
  const title = breadcrumbs.at(-1)?.label ?? t('pageTitleFallback')

  useEffect(() => {
    document.title = `${title} - ${config.displayName}`
  }, [config.displayName, title])

  function toggleSidebar() {
    setCollapsed((current) => {
      const next = !current
      try {
        window.localStorage.setItem(SIDEBAR_STORAGE_KEY, next ? '1' : '0')
      } catch {
        // The layout still collapses when storage is unavailable.
      }
      return next
    })
  }

  // Signing out ends the Identity session as well, so the next sign-in asks
  // for credentials instead of silently restoring the same account. Without
  // an end-session endpoint the console still clears its own session.
  function signOut() {
    if (!logoutSso()) void navigate({ to: '/signed-out', replace: true })
  }

  function switchAccount() {
    // Explicit account selection on a normal sign-in. The current page is kept
    // as the safe return target, and no single sign-out is started first.
    void signIn({ selectAccount: true, returnTo: currentReturnTo() })
  }

  return (
    <>
      <Toaster position="bottom-right" closeButton />
      <div className="flex min-h-screen bg-background text-foreground">
        <aside
          id="console-sidebar"
          className={`sticky top-0 hidden h-screen shrink-0 flex-col border-r border-border bg-card transition-[width] duration-200 lg:flex ${
            collapsed ? 'w-[72px]' : 'w-[240px]'
          }`}
        >
          <div
            className={`flex h-16 shrink-0 items-center border-b border-border ${collapsed ? 'justify-center px-2' : 'px-4'}`}
          >
            <Brand displayName={config.displayName} collapsed={collapsed} />
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto p-2">
            <NavigationLinks collapsed={collapsed} />
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-20 h-16 shrink-0 border-b border-border bg-card/90 backdrop-blur-md">
            <div className="flex h-full items-center gap-2 px-4 sm:px-5 lg:px-6">
              <MobileNavigation displayName={config.displayName} />
              <div className="hidden shrink-0 lg:flex">
                <SidebarCollapseButton
                  collapsed={collapsed}
                  onToggle={toggleSidebar}
                />
              </div>
              <div className="min-w-0 flex-1">
                <AppBreadcrumbs items={breadcrumbs} />
                <p className="truncate text-sm font-medium text-foreground md:hidden">
                  {title}
                </p>
              </div>

              <div className="flex shrink-0 items-center gap-0.5">
                <AccountMenu
                  name={name}
                  email={email}
                  picture={picture}
                  accountUrl={config.accountUrl}
                  onSwitchAccount={switchAccount}
                  onSignOut={signOut}
                />
              </div>
            </div>
          </header>

          <main className="mx-auto w-full max-w-[1280px] flex-1 px-4 py-6 sm:px-5 lg:px-6">
            <Outlet />
          </main>
        </div>

      </div>
    </>
  )
}
