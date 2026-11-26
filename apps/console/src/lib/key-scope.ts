import { fieldAffordance } from '#/lib/graphql/affordances'
import type { EffectivePermissions } from '#/lib/workspace'

/** Visible key actions, derived from the executable field declarations. */
export function keyScope(permissions: EffectivePermissions | null | undefined) {
  return {
    read: fieldAffordance(permissions, 'query', 'keys'),
    create: fieldAffordance(permissions, 'mutation', 'createSigningKey'),
    rotate: fieldAffordance(permissions, 'mutation', 'rotateKey'),
    revoke: fieldAffordance(permissions, 'mutation', 'revokeKey'),
    rotateAndRevoke: fieldAffordance(permissions, 'mutation', 'rotateAndRevokeKey'),
  }
}

export type KeyScope = ReturnType<typeof keyScope>
