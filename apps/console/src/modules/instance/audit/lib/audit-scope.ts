import { fieldAffordance } from '#/lib/graphql/affordances'
import type { EffectivePermissions } from '#/lib/workspace'

/** Visible audit read capabilities, derived from the executable schema declarations. */
export function auditScope(permissions: EffectivePermissions | null | undefined) {
  return {
    read: fieldAffordance(permissions, 'query', 'auditEvents'),
    readDetail: fieldAffordance(permissions, 'query', 'auditEvent'),
    readActorUser: fieldAffordance(permissions, 'AuditActor', 'user'),
    readActorClient: fieldAffordance(permissions, 'AuditActor', 'client'),
  }
}

export type AuditScope = ReturnType<typeof auditScope>
