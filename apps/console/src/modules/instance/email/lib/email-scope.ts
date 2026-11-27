import { useMemo } from 'react'

import { fieldAffordance } from '#/lib/graphql/affordances'
import { useWorkspace, type EffectivePermissions } from '#/lib/workspace'

/** Visible email actions, derived from the executable field declarations. */
export function emailScope(permissions: EffectivePermissions | null | undefined) {
  return {
    deliveryWrite: fieldAffordance(permissions, 'mutation', 'updateEmailDeliverySettings'),
    policyWrite: fieldAffordance(permissions, 'mutation', 'updateEmailPolicySettings'),
    templateWrite: fieldAffordance(permissions, 'mutation', 'updateEmailTemplate'),
    testEmail: fieldAffordance(permissions, 'mutation', 'sendTestEmail'),
    preview: fieldAffordance(permissions, 'query', 'emailTemplatePreview'),
  }
}

export type EmailScope = ReturnType<typeof emailScope>

export function useEmailScope(): EmailScope {
  const permissions = useWorkspace().data?.effectivePermissions
  return useMemo(() => emailScope(permissions), [permissions])
}
