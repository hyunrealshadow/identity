import type { AuditEventFieldsFragment } from '#/generated/graphql'
import type { MessageKey } from '#/lib/i18n'
import { resolveLocalizedText } from '#/modules/user-management/groups/lib/groups-search'
import {
  AUDIT_ACTION_LABELS,
  AUDIT_ACTOR_KIND_LABELS,
  AUDIT_TARGET_KIND_LABELS,
} from './audit-labels'

type Translate = (key: MessageKey) => string

/**
 * Who performed the event: the live account when it is readable, then the
 * name recorded with the event, then the kind of actor.
 */
export function auditActorName(
  event: AuditEventFieldsFragment,
  locale: string,
  t: Translate,
): string {
  const { actor } = event
  if (actor.user) return actor.user.nickname?.trim() || actor.user.username
  if (actor.client) return resolveLocalizedText(actor.client.names, locale) ?? actor.client.name
  if (actor.label) return actor.label
  if (actor.oid) return `${t(AUDIT_ACTOR_KIND_LABELS[actor.kind])} ${actor.oid.slice(0, 8)}`
  return t(AUDIT_ACTOR_KIND_LABELS[actor.kind])
}

/** The object of the event: its recorded name, else its kind and short OID. */
export function auditTargetName(event: AuditEventFieldsFragment, t: Translate): string | null {
  const { target } = event
  if (!target) return null
  return target.label ?? `${t(AUDIT_TARGET_KIND_LABELS[target.kind])} ${target.oid.slice(0, 8)}`
}

export function auditActionLabel(event: AuditEventFieldsFragment, t: Translate): string {
  return t(AUDIT_ACTION_LABELS[event.action])
}

/** Compact display of a recorded change value or collection member. */
export function auditChangeValueText(value: unknown, emptyLabel: string): string {
  if (value === null || value === undefined || value === '') return emptyLabel
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (Array.isArray(value)) {
    const items = value
      .map((item) => auditChangeValueText(item, ''))
      .filter((item) => item !== '')
    return items.length > 0 ? items.join(', ') : emptyLabel
  }
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>
    // A recorded reference to another object.
    if (typeof record.oid === 'string') {
      return typeof record.label === 'string' ? record.label : record.oid.slice(0, 8)
    }
    // A localized text entry.
    if (typeof record.locale === 'string' && typeof record.value === 'string') {
      return `${record.locale}: ${record.value}`
    }
  }
  return JSON.stringify(value)
}
