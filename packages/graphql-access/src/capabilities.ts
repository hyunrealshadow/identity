import { schemaMetadata as defaultSchema } from './schema'
import type { SchemaField, SchemaMetadata } from './types'

/**
 * Live permission scope sets returned by `QueryRoot.effectivePermissions`.
 */
export interface EffectivePermissionScopes {
  requestableScopes?: readonly string[] | null
  effectiveScopes?: readonly string[] | null
}

function fieldRequiredManagementScopes(field: SchemaField): string[] | undefined {
  // Self-service security mutations pair a non-runtime scope policy with an
  // empty-scope `ACCOUNT_SECURITY` runtime policy, so only a single policy
  // declaring both `runtime` and at least one scope marks a management field.
  const hasRuntimeScopedPolicy = field.policies.some(
    (policy) => policy.runtime && policy.scopes.length > 0,
  )
  if (!hasRuntimeScopedPolicy) return undefined

  const required = new Set<string>()
  for (const policy of field.policies) {
    for (const scope of policy.scopes) {
      required.add(scope)
    }
  }
  return required.size > 0 ? Array.from(required) : undefined
}

/**
 * Returns true when the user's live scopes satisfy at least one management
 * field in the executable schema metadata, ignoring authentication assurance
 * and freshness.
 */
export function hasManagementAccess(
  permissions: EffectivePermissionScopes | null | undefined,
  schema: SchemaMetadata = defaultSchema,
): boolean {
  if (!permissions) return false

  const granted = new Set<string>([
    ...(permissions.requestableScopes ?? []),
    ...(permissions.effectiveScopes ?? []),
  ])
  if (granted.size === 0) return false

  const typeNames = [schema.queryTypeName, schema.mutationTypeName, 'InstanceOverview']
  for (const typeName of typeNames) {
    if (!typeName) continue
    const schemaType = schema.types[typeName]
    if (!schemaType) continue
    for (const field of Object.values(schemaType.fields)) {
      const required = fieldRequiredManagementScopes(field)
      if (required && required.every((scope) => granted.has(scope))) {
        return true
      }
    }
  }
  return false
}
