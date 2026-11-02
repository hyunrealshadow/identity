import { fieldAffordance } from '#/lib/graphql/affordances'
import type { EffectivePermissions } from '#/lib/workspace'

export function dashboardScope(
  permissions: EffectivePermissions | null | undefined,
) {
  const users = fieldAffordance(permissions, 'InstanceOverview', 'users')
  const applications = fieldAffordance(
    permissions,
    'InstanceOverview',
    'applications',
  )
  const sessions = fieldAffordance(permissions, 'InstanceOverview', 'sessions')
  const resources = fieldAffordance(
    permissions,
    'InstanceOverview',
    'resources',
  )
  return {
    users,
    applications,
    sessions,
    resources,
    hasAny: users || applications || sessions || resources,
  }
}

export type DashboardScope = ReturnType<typeof dashboardScope>
