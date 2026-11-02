import {
  Alert,
  Button,
  Dropdown,
  Label,
  Modal,
  Spinner,
  Toast,
  useOverlayState,
  useTheme,
} from '@heroui/react'
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
    <Dropdown>
      <Button
        variant="ghost"
        size="sm"
        aria-label={label}
        className="h-10 max-w-64 gap-2 px-1.5"
      >
        <AccountAvatar
          name={name}
          picture={picture}
          label={avatarLabel}
          size="sm"
        />
        <span className="hidden min-w-0 text-start sm:block">
          <span className="block truncate text-sm font-medium">{name}</span>
          <span className="block truncate text-xs font-normal text-muted">
            {email}
          </span>
        </span>
        <ChevronDown
          className="hidden size-3.5 text-muted sm:block"
          aria-hidden="true"
        />
      </Button>
      <Dropdown.Popover placement="bottom end" className="min-w-56">
        <Dropdown.Menu
          aria-label={label}
          onAction={(key) => {
            if (key === 'switch-account') onSwitchAccount()
            if (key === 'signout') onSignOut()
          }}
        >
          <Dropdown.Item
            id="account-center"
            href={accountUrl}
            textValue={t('accountCenter')}
          >
            <ExternalLink className="size-4 text-muted" aria-hidden="true" />
            <Label>{t('accountCenter')}</Label>
          </Dropdown.Item>
          <Dropdown.Item id="switch-account" textValue={t('switchAccount')}>
            <ArrowLeftRight className="size-4 text-muted" aria-hidden="true" />
            <Label>{t('switchAccount')}</Label>
          </Dropdown.Item>
          <Dropdown.Item
            id="signout"
            textValue={t('signOut')}
            className="text-danger"
          >
            <LogOut className="size-4" aria-hidden="true" />
            <Label>{t('signOut')}</Label>
          </Dropdown.Item>
        </Dropdown.Menu>
      </Dropdown.Popover>
    </Dropdown>
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
  const { claims, ssoAvailable, signIn, logoutLocal, logoutSso } = useAuth()
  const { theme, setTheme } = useTheme()
  const navigate = useNavigate()
  const [collapsed, setCollapsed] = useState(readCollapsed)
  const [logoutPending, setLogoutPending] = useState(false)
  const logoutState = useOverlayState()

  const name = displayName(claims, t('unknown'))
  const email = emailOf(claims)
  const picture = claims?.picture
  const breadcrumbs = usePageBreadcrumbs()
  const title = breadcrumbs.at(-1)?.label ?? t('pageTitleFallback')

  useEffect(() => {
    if (theme !== 'light' && theme !== 'dark' && theme !== 'system')
      setTheme('system')
  }, [setTheme, theme])

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

  function signOutLocal() {
    setLogoutPending(true)
    logoutLocal()
    logoutState.close()
    void navigate({ to: '/signed-out', replace: true })
  }

  function signOutSso() {
    setLogoutPending(true)
    const redirected = logoutSso()
    if (!redirected) {
      logoutLocal()
      logoutState.close()
      void navigate({ to: '/signed-out', replace: true })
    }
  }

  function switchAccount() {
    logoutState.close()
    // Explicit account selection on a normal sign-in. The current page is kept
    // as the safe return target, and no single sign-out is started first.
    void signIn({ selectAccount: true, returnTo: currentReturnTo() })
  }

  return (
    <>
      <Toast.Provider placement="bottom end" maxVisibleToasts={3}>
        {({ toast }) => (
          <Toast toast={toast} variant={toast.content.variant}>
            <Toast.Indicator variant={toast.content.variant} />
            <Toast.Content>
              <Toast.Title>{toast.content.title}</Toast.Title>
              {toast.content.description ? (
                <Toast.Description>
                  {toast.content.description}
                </Toast.Description>
              ) : null}
            </Toast.Content>
            <Toast.CloseButton aria-label={t('close')} />
          </Toast>
        )}
      </Toast.Provider>
      <div className="flex min-h-screen bg-background text-foreground">
        <aside
          id="console-sidebar"
          className={`sticky top-0 hidden h-screen shrink-0 flex-col border-r border-border bg-surface transition-[width] duration-200 lg:flex ${
            collapsed ? 'w-[72px]' : 'w-[240px]'
          }`}
        >
          <div
            className={`flex h-16 shrink-0 items-center border-b border-separator ${collapsed ? 'justify-center px-2' : 'px-4'}`}
          >
            <Brand displayName={config.displayName} collapsed={collapsed} />
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto p-2">
            <NavigationLinks collapsed={collapsed} />
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-20 h-16 shrink-0 border-b border-border bg-surface/90 backdrop-blur-md">
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
                  onSignOut={() => logoutState.open()}
                />
              </div>
            </div>
          </header>

          <main className="mx-auto w-full max-w-[1280px] flex-1 px-4 py-6 sm:px-5 lg:px-6">
            <Outlet />
          </main>
        </div>

        <Modal state={logoutState}>
          <Modal.Backdrop isDismissable={!logoutPending}>
            <Modal.Container size="md">
              <Modal.Dialog>
                {({ close }) => (
                  <>
                    <Modal.CloseTrigger
                      aria-label={t('close')}
                      isDisabled={logoutPending}
                    />
                    <Modal.Header>
                      <Modal.Heading>{t('signOutTitle')}</Modal.Heading>
                    </Modal.Header>
                    <Modal.Body>
                      <p className="text-sm leading-6 text-muted">
                        {t('signOutDescription')}
                      </p>
                      <div className="mt-4 grid gap-3 sm:grid-cols-2">
                        <div className="rounded-field border border-border p-3">
                          <p className="text-sm font-medium">
                            {t('signOutLocalTitle')}
                          </p>
                          <p className="mt-1 text-xs leading-5 text-muted">
                            {t('signOutLocalDescription')}
                          </p>
                        </div>
                        <div className="rounded-field border border-border p-3">
                          <p className="text-sm font-medium">
                            {t('signOutSsoTitle')}
                          </p>
                          <p className="mt-1 text-xs leading-5 text-muted">
                            {t('signOutSsoDescription')}
                          </p>
                        </div>
                      </div>
                      {!ssoAvailable ? (
                        <Alert status="warning" className="mt-3">
                          <Alert.Indicator />
                          <Alert.Content>
                            <Alert.Description>
                              {t('signOutSsoUnavailable')}
                            </Alert.Description>
                          </Alert.Content>
                        </Alert>
                      ) : null}
                    </Modal.Body>
                    <Modal.Footer>
                      <Button
                        type="button"
                        variant="ghost"
                        isDisabled={logoutPending}
                        onPress={close}
                      >
                        {t('cancel')}
                      </Button>
                      <Button
                        type="button"
                        variant="secondary"
                        isDisabled={logoutPending}
                        onPress={signOutLocal}
                      >
                        {t('signOutLocalAction')}
                      </Button>
                      <Button
                        type="button"
                        variant="danger"
                        isDisabled={logoutPending || !ssoAvailable}
                        onPress={signOutSso}
                      >
                        {logoutPending ? (
                          <Spinner size="sm" aria-label={t('signOutPending')} />
                        ) : null}
                        {t('signOutSsoAction')}
                      </Button>
                    </Modal.Footer>
                  </>
                )}
              </Modal.Dialog>
            </Modal.Container>
          </Modal.Backdrop>
        </Modal>
      </div>
    </>
  )
}
