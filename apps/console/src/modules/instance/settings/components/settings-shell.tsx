import { Link, Outlet, useNavigate, useRouterState } from '@tanstack/react-router'
import { createContext, useContext, useMemo, type ReactNode } from 'react'

import { AsyncState } from '#/components/async-state'
import { PageHeader } from '#/components/page-header'
import {
  ConsoleInstanceSettingsDocument,
  type ConsoleInstanceSettingsQuery,
  type ConsoleInstanceSettingsQueryVariables,
} from '#/generated/graphql'
import { failureDescriptionKey, failureTitleKey } from '#/lib/graphql/presentation'
import { useConsoleQuery, type ConsoleQueryState } from '#/lib/graphql/use-console-query'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import { ConsoleWorkspaceGate } from '#/modules/user-management/components/workspace-gate'
import { RbacAccessRestricted } from '#/modules/user-management/roles/components/role-access'
import { keyScope, type KeyScope } from '../../keys/lib/key-scope'
import type { InstanceSettings } from '../lib/settings-form'
import { settingsScope, type SettingsScope } from '../lib/settings-scope'

interface SettingsContextValue {
  settings: InstanceSettings | null
  query: ConsoleQueryState<ConsoleInstanceSettingsQuery>
  scope: SettingsScope
  keys: KeyScope
  /** Workspace permissions are still loading, so a missing scope is not yet a denial. */
  permissionsPending: boolean
}

const SettingsContext = createContext<SettingsContextValue | null>(null)

export function useInstanceSettings() {
  const value = useContext(SettingsContext)
  if (!value) throw new Error('Instance settings context is missing')
  return value
}

type SettingsPath =
  | '/settings'
  | '/settings/protocol'
  | '/settings/authentication'
  | '/settings/signing-keys'
  | '/settings/encryption-keys'

const tabs: ReadonlyArray<{
  to: SettingsPath
  label: MessageKey
  /** Which read the tab's content needs. */
  read: 'settings' | 'keys'
}> = [
  { to: '/settings', label: 'settingsTabGeneral', read: 'settings' },
  { to: '/settings/protocol', label: 'settingsTabProtocol', read: 'settings' },
  { to: '/settings/authentication', label: 'settingsTabAuthentication', read: 'settings' },
  { to: '/settings/signing-keys', label: 'settingsTabSigningKeys', read: 'keys' },
  { to: '/settings/encryption-keys', label: 'settingsTabEncryptionKeys', read: 'keys' },
]

function activeTab(pathname: string): SettingsPath {
  const path = pathname.replace(/\/+$/u, '')
  return (
    tabs.find((tab) => tab.to !== '/settings' && path.endsWith(tab.to))?.to ?? '/settings'
  )
}

const noVariables: ConsoleInstanceSettingsQueryVariables = {}

export function SettingsShell() {
  const t = useTranslator()
  const workspace = useWorkspace()
  const permissions = workspace.data?.effectivePermissions
  const scope = useMemo(() => settingsScope(permissions), [permissions])
  const keys = useMemo(() => keyScope(permissions), [permissions])
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  const query = useConsoleQuery<
    ConsoleInstanceSettingsQuery,
    ConsoleInstanceSettingsQueryVariables
  >(
    ConsoleInstanceSettingsDocument,
    scope.read ? noVariables : null,
    scope.read,
    'missing_instance_settings',
  )
  const settings = query.data?.instanceSettings ?? null
  const permissionsPending =
    !permissions && (workspace.status === 'idle' || workspace.status === 'loading')
  const current = activeTab(pathname)
  // Every tab stays while permissions load, so the row does not jump.
  const visible = tabs.filter(
    (tab) =>
      permissionsPending ||
      tab.to === current ||
      (tab.read === 'settings' ? scope.read : keys.read),
  )

  const context = useMemo(
    () => ({ settings, query, scope, keys, permissionsPending }),
    [settings, query, scope, keys, permissionsPending],
  )

  return (
    <SettingsContext.Provider value={context}>
      <PageHeader title={t('settingsTitle')} description={t('settingsDescription')} />
      <nav aria-label={t('settingsTabs')} className="mb-6 border-b border-border">
        <div className="flex gap-1 overflow-x-auto">
          {visible.map((tab) => {
            const active = tab.to === current
            return (
              <Link
                key={tab.to}
                to={tab.to}
                className={
                  'shrink-0 border-b-2 px-3 py-2.5 text-sm ' +
                  (active ? 'border-primary font-semibold' : 'border-transparent text-muted-foreground')
                }
                aria-current={active ? 'page' : undefined}
              >
                {t(tab.label)}
              </Link>
            )
          })}
        </div>
      </nav>
      {/* While permissions load, the routed page shows its own skeleton. */}
      <ConsoleWorkspaceGate loading={<Outlet />}>
        <Outlet />
      </ConsoleWorkspaceGate>
    </SettingsContext.Provider>
  )
}

/**
 * What a settings section shows instead of its content when the settings
 * cannot be read: an access notice or the read failure. Null means render.
 */
export function useSettingsBlocker(): ReactNode | null {
  const t = useTranslator()
  const navigate = useNavigate()
  const { scope, query, permissionsPending } = useInstanceSettings()
  if (!scope.read && !permissionsPending) {
    return (
      <RbacAccessRestricted
        title="settingsNoReadTitle"
        description="settingsNoReadDescription"
        onBack={() => void navigate({ to: '/' })}
        backLabel="goHome"
      />
    )
  }
  if (query.status === 'error') {
    return (
      <AsyncState
        kind={query.forbidden ? 'forbidden' : 'error'}
        title={t(failureTitleKey(query.failure, query.forbidden))}
        description={t(failureDescriptionKey(query.failure, query.forbidden))}
        requestId={query.requestId}
        traceId={query.traceId}
        issues={query.errors}
        onRetry={() => void query.refresh()}
      />
    )
  }
  return null
}
