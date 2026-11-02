import type { EffectivePermissions } from '#/lib/workspace'

export const DASHBOARD_READ_SCOPES = {
  users: 'management.user.read',
  applications: 'management.client.read',
  sessions: 'management.session.read',
  resources: 'management.resource.read',
} as const

const READ_SCOPES = Object.values(DASHBOARD_READ_SCOPES)

export interface DashboardScope {
  users: boolean
  applications: boolean
  sessions: boolean
  resources: boolean
  hasAny: boolean
  /** No effective read access, but stronger authentication could unlock it. */
  stepUp: boolean
}

const EMPTY_SCOPE: DashboardScope = {
  users: false,
  applications: false,
  sessions: false,
  resources: false,
  hasAny: false,
  stepUp: false,
}

function hasAnyRead(values: ReadonlyArray<string>): boolean {
  return READ_SCOPES.some((scope) => values.includes(scope))
}

/**
 * Derive the dashboard query selection and local authorization state from the
 * bootstrap permissions. The backend remains authoritative for every module.
 */
export function dashboardScope(
  permissions: EffectivePermissions | null | undefined,
): DashboardScope {
  if (!permissions) return EMPTY_SCOPE

  const effective = new Set(permissions.effectiveScopes)
  const users = effective.has(DASHBOARD_READ_SCOPES.users)
  const applications = effective.has(DASHBOARD_READ_SCOPES.applications)
  const sessions = effective.has(DASHBOARD_READ_SCOPES.sessions)
  const resources = effective.has(DASHBOARD_READ_SCOPES.resources)
  const hasAny = users || applications || sessions || resources

  const authentication = permissions.authentication
  const requestable = [...permissions.requestableScopes, ...permissions.grantedScopes]
  const stepUp =
    !hasAny &&
    authentication?.aal2 !== true &&
    hasAnyRead(requestable)

  return { users, applications, sessions, resources, hasAny, stepUp }
}
