import { fieldAffordance } from '#/lib/graphql/affordances'
import type { EffectivePermissions } from '#/lib/workspace'

/** Visible settings actions, derived from the executable field declarations. */
export function settingsScope(permissions: EffectivePermissions | null | undefined) {
  return {
    read: fieldAffordance(permissions, 'query', 'instanceSettings'),
    protocolWrite: fieldAffordance(permissions, 'mutation', 'updateProtocolSettings'),
    authenticationWrite: fieldAffordance(
      permissions,
      'mutation',
      'updateAuthenticationSettings',
    ),
    emailWrite: fieldAffordance(permissions, 'mutation', 'updateEmailDeliverySettings'),
    emailTemplateWrite: fieldAffordance(permissions, 'mutation', 'updateEmailTemplate'),
    testEmail: fieldAffordance(permissions, 'mutation', 'sendTestEmail'),
    emailPreview: fieldAffordance(permissions, 'query', 'emailTemplatePreview'),
  }
}

export type SettingsScope = ReturnType<typeof settingsScope>
