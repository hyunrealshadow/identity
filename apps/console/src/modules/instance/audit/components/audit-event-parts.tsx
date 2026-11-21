import { Badge } from '@identity/ui/components/badge'
import { Fragment } from 'react'

import type { AuditEventFieldsFragment } from '#/generated/graphql'
import { useTranslator } from '#/lib/i18n'
import { AUDIT_FAILURE_REASON_LABELS, AUDIT_OUTCOME_LABELS } from '../lib/audit-labels'
import { auditSentence } from '../lib/audit-presentation'

/** The event sentence with its actor and target emphasized. */
export function AuditEventSentence({
  event,
  locale,
}: {
  event: AuditEventFieldsFragment
  locale: string
}) {
  const t = useTranslator()
  return (
    <>
      {auditSentence(event, locale, t).map((part, index) =>
        part.role ? (
          <span key={index} className="font-medium text-foreground">
            {part.text}
          </span>
        ) : (
          <Fragment key={index}>{part.text}</Fragment>
        ),
      )}
    </>
  )
}

export function AuditOutcomeBadge({ event }: { event: AuditEventFieldsFragment }) {
  const t = useTranslator()
  if (event.outcome === 'SUCCESS') {
    return <Badge variant="outline">{t(AUDIT_OUTCOME_LABELS.SUCCESS)}</Badge>
  }
  return (
    <Badge variant="destructive">
      {event.failureReason
        ? t(AUDIT_FAILURE_REASON_LABELS[event.failureReason])
        : t(AUDIT_OUTCOME_LABELS.FAILURE)}
    </Badge>
  )
}
