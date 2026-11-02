import { schemaMetadata } from '@identity/graphql-access'

import type { EffectivePermissions } from '#/lib/workspace'

/** Only choose visible fields/actions. Actual documents and variables are preflighted by useGraphQL. */
export function fieldAffordance(
  permissions: EffectivePermissions | null | undefined,
  type: 'query' | 'mutation' | string,
  field: string,
): boolean {
  if (!permissions) return false
  const name =
    type === 'query'
      ? schemaMetadata.queryTypeName
      : type === 'mutation'
        ? schemaMetadata.mutationTypeName
        : type
  const policies = name
    ? schemaMetadata.types[name]?.fields[field]?.policies
    : undefined
  if (!policies?.length) return false
  // Historical token scopes cannot restore a capability withdrawn by the live bootstrap snapshot.
  const eligible = new Set([
    ...permissions.effectiveScopes,
    ...permissions.requestableScopes,
  ])
  return policies.every((policy) =>
    policy.scopes.every((scope) => eligible.has(scope)),
  )
}
