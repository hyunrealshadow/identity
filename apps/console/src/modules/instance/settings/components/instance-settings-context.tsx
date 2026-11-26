import { useNavigate } from '@tanstack/react-router'
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'

import { AsyncState } from '#/components/async-state'
import {
  ConsoleInstanceSettingsDocument,
  type ConsoleInstanceSettingsQuery,
  type ConsoleInstanceSettingsQueryVariables,
} from '#/generated/graphql'
import { failureDescriptionKey, failureTitleKey } from '#/lib/graphql/presentation'
import { useConsoleQuery, type ConsoleQueryState } from '#/lib/graphql/use-console-query'
import { useTranslator } from '#/lib/i18n'
import { useWorkspace } from '#/lib/workspace'
import { RbacAccessRestricted } from '#/components/role-access'
import { keyScope, type KeyScope } from '#/lib/key-scope'
import type { InstanceSettings } from '../lib/settings-form'
import { settingsScope, type SettingsScope } from '../lib/settings-scope'

interface InstanceSettingsContextValue {
  settings: InstanceSettings | null
  query: ConsoleQueryState<ConsoleInstanceSettingsQuery>
  scope: SettingsScope
  keys: KeyScope
  /** Workspace permissions are still loading, so a missing scope is not yet a denial. */
  permissionsPending: boolean
  /** Unsaved edits by section and version; see {@link useSettingsDraft}. */
  drafts: Map<string, unknown>
}

const InstanceSettingsContext = createContext<InstanceSettingsContextValue | null>(null)

export function useInstanceSettings() {
  const value = useContext(InstanceSettingsContext)
  if (!value) throw new Error('Instance settings context is missing')
  return value
}

const noVariables: ConsoleInstanceSettingsQueryVariables = {}

/**
 * The stored instance settings and what the signed-in user may do with them,
 * shared by the settings and email areas, which edit sections of the same
 * versioned settings.
 */
export function InstanceSettingsProvider({ children }: { children: ReactNode }) {
  const workspace = useWorkspace()
  const permissions = workspace.data?.effectivePermissions
  const scope = useMemo(() => settingsScope(permissions), [permissions])
  const keys = useMemo(() => keyScope(permissions), [permissions])
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
  // Kept here rather than in each form: replacing the session (for example
  // after reauthentication) empties the read cache, which unmounts the forms
  // until the settings are read again with the new session.
  const drafts = useRef(new Map<string, unknown>()).current
  const value = useMemo(
    () => ({ settings, query, scope, keys, permissionsPending, drafts }),
    [settings, query, scope, keys, permissionsPending, drafts],
  )
  return (
    <InstanceSettingsContext.Provider value={value}>{children}</InstanceSettingsContext.Provider>
  )
}

/**
 * Form state for one version of one settings section that survives the form
 * being unmounted while the settings are read again. A draft is restored only
 * for the version it was made against; once the section changes, the form
 * starts from the stored values. `reset` forgets the draft after a save or a
 * discard.
 */
export function useSettingsDraft<T>(
  section: string,
  version: string,
  initial: () => T,
): readonly [T, (next: T | ((current: T) => T)) => void, () => void] {
  const { drafts } = useInstanceSettings()
  const key = `${section}\0${version}`
  const [draft, setDraft] = useState<T>(() =>
    drafts.has(key) ? (drafts.get(key) as T) : initial(),
  )
  const update = useCallback(
    (next: T | ((current: T) => T)) => {
      setDraft((current) => {
        const value =
          typeof next === 'function' ? (next as (current: T) => T)(current) : next
        for (const stored of drafts.keys()) {
          if (stored.startsWith(`${section}\0`) && stored !== key) drafts.delete(stored)
        }
        drafts.set(key, value)
        return value
      })
    },
    [drafts, key, section],
  )
  const reset = useCallback(() => {
    drafts.delete(key)
    setDraft(initial())
    // `initial` reads the stored values of this version.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [drafts, key])
  return [draft, update, reset] as const
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
