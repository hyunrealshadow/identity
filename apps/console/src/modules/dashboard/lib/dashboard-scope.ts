import { fieldAffordance } from '#/lib/graphql/affordances'
import type { EffectivePermissions } from '#/lib/workspace'

export function dashboardScope(
  permissions: EffectivePermissions | null | undefined,
) {
  const users = fieldAffordance(permissions, 'InstanceOverview', 'users')
  const clients = fieldAffordance(
    permissions,
    'InstanceOverview',
    'clients',
  )
  const sessions = fieldAffordance(permissions, 'InstanceOverview', 'sessions')
  const resources = fieldAffordance(
    permissions,
    'InstanceOverview',
    'resources',
  )
  return {
    users,
    clients,
    sessions,
    resources,
    hasAny: users || clients || sessions || resources,
  }
}

export type DashboardScope = ReturnType<typeof dashboardScope>
