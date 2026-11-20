import type { MessageKey } from '#/lib/i18n'

type Translate = (key: MessageKey) => string

const ACTOR_TYPE_LABELS: Readonly<Record<string, MessageKey>> = {
  user: 'auditActorTypeUser',
  client: 'auditActorTypeClient',
  system: 'auditActorTypeSystem',
  unknown: 'auditActorTypeUnknown',
}

const OPERATION_LABELS: Readonly<Record<string, MessageKey>> = {
  mutation: 'auditOperationMutation',
  authorization: 'auditOperationAuthorization',
}

const STATUS_LABELS: Readonly<Record<string, MessageKey>> = {
  success: 'auditStatusSuccess',
  failed: 'auditStatusFailed',
}

const EVENT_KIND_LABELS: Readonly<Record<string, MessageKey>> = {
  semantic: 'auditEventKindSemantic',
}

const ENTITY_TYPE_LABELS: Readonly<Record<string, MessageKey>> = {
  user: 'auditEntityUser',
  client: 'auditEntityClient',
  resource: 'auditEntityResource',
  scope: 'auditEntityScope',
  role: 'auditEntityRole',
  user_group: 'auditEntityUserGroup',
  session: 'auditEntitySession',
  key: 'auditEntityKey',
  setting: 'auditEntitySetting',
  login: 'auditEntityLogin',
  user_credential: 'auditEntityUserCredential',
  group_membership: 'auditEntityGroupMembership',
  group_role: 'auditEntityGroupRole',
  user_role: 'auditEntityUserRole',
  client_authorization: 'auditEntityClientAuthorization',
  device_authorization: 'auditEntityDeviceAuthorization',
  device_authorization_request: 'auditEntityDeviceAuthorizationRequest',
}

export const AUDIT_VALUE_LABELS = {
  actorType: ACTOR_TYPE_LABELS,
  operation: OPERATION_LABELS,
  status: STATUS_LABELS,
  eventKind: EVENT_KIND_LABELS,
  entityType: ENTITY_TYPE_LABELS,
} as const

export type AuditValueKind = keyof typeof AUDIT_VALUE_LABELS

/**
 * Display label for a stored audit enum value. Values the Console does not
 * know yet (newer backend types) stay visible as their raw value.
 */
export function auditValueLabel(
  t: Translate,
  kind: AuditValueKind,
  value: string,
): string
export function auditValueLabel(
  t: Translate,
  kind: AuditValueKind,
  value: string | null | undefined,
): string | null
export function auditValueLabel(
  t: Translate,
  kind: AuditValueKind,
  value: string | null | undefined,
): string | null {
  if (value == null) return null
  const key = AUDIT_VALUE_LABELS[kind][value]
  return key ? t(key) : value
}
