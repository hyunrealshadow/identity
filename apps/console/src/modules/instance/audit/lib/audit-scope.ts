import { fieldAffordance } from '#/lib/graphql/affordances'
import type { EffectivePermissions } from '#/lib/workspace'

/** Visible audit read capabilities, derived from the executable schema declarations. */
export function auditScope(permissions: EffectivePermissions | null | undefined) {
  return {
    read: fieldAffordance(permissions, 'query', 'auditEvents'),
    readDetail: fieldAffordance(permissions, 'query', 'auditEvent'),
    readActions: fieldAffordance(permissions, 'query', 'auditEventActions'),
    readActorUser: fieldAffordance(permissions, 'AuditEvent', 'actorUser'),
    readActorClient: fieldAffordance(permissions, 'AuditEvent', 'actorClient'),
  }
}

export type AuditScope = ReturnType<typeof auditScope>
