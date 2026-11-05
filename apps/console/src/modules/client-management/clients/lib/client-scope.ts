import { fieldAffordance } from '#/lib/graphql/affordances'
import type { EffectivePermissions } from '#/lib/workspace'

/** Visible client actions, derived from the executable field declarations. */
export function clientScope(
  permissions: EffectivePermissions | null | undefined,
) {
  const mutation = (field: string) =>
    fieldAffordance(permissions, 'mutation', field)
  return {
    read: fieldAffordance(permissions, 'query', 'clients'),
    create: mutation('createClient'),
    update: mutation('updateClient'),
    state: mutation('disableClient'),
    delete: mutation('deleteClient'),
    credentialsRead: fieldAffordance(permissions, 'Client', 'credentials'),
    secretCreate: mutation('createClientSecret'),
    secretRotate: mutation('rotateClientSecret'),
    credentialRevoke: mutation('revokeClientCredential'),
    scopesWrite: mutation('setClientScopes'),
  }
}

export type ClientScope = ReturnType<typeof clientScope>
