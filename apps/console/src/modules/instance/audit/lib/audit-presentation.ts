import type { AuditEventFieldsFragment } from '#/generated/graphql'
import type { MessageKey } from '#/lib/i18n'
import { resolveLocalizedText } from '#/lib/localized-metadata'
import {
  AUDIT_ACTION_LABELS,
  AUDIT_ACTOR_KIND_LABELS,
  AUDIT_SENTENCE_LABELS,
  AUDIT_SENTENCE_WITHOUT_TARGET_LABELS,
  AUDIT_TARGET_KIND_LABELS,
} from './audit-labels'

type Translate = (key: MessageKey, values?: Record<string, string | number>) => string

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

export interface AuditSentencePart {
  text: string
  /** Set on the parts naming the actor or the target. */
  role?: 'actor' | 'target'
}

const ACTOR_MARK = '\u0001'
const TARGET_MARK = '\u0002'

/**
 * The event as a localized sentence, such as "alice updated role Auditors",
 * split so the actor and target can be emphasized.
 */
export function auditSentence(
  event: AuditEventFieldsFragment,
  locale: string,
  t: Translate,
): AuditSentencePart[] {
  const key =
    (event.target ? undefined : AUDIT_SENTENCE_WITHOUT_TARGET_LABELS[event.action]) ??
    AUDIT_SENTENCE_LABELS[event.action]
  const template = t(key, {
    actor: ACTOR_MARK,
    target: TARGET_MARK,
  })
  const actor = auditActorName(event, locale, t)
  const target = auditTargetName(event, t) ?? t('auditTargetUnknown')
  return template
    .split(/([\u0001\u0002])/u)
    .filter((part) => part !== '')
    .map((part) =>
      part === ACTOR_MARK
        ? { text: actor, role: 'actor' as const }
        : part === TARGET_MARK
          ? { text: target, role: 'target' as const }
          : { text: part },
    )
}

export function auditSentenceText(
  event: AuditEventFieldsFragment,
  locale: string,
  t: Translate,
): string {
  return auditSentence(event, locale, t)
    .map((part) => part.text)
    .join('')
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
