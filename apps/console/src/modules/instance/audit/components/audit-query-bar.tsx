import {
  LuceneInput,
  getLuceneDiagnostics,
  type ComponentDiagnostic,
  type LuceneField,
} from '@identity/lucene-input'
import { Alert, AlertDescription, AlertTitle } from '@identity/ui/components/alert'
import { Button } from '@identity/ui/components/button'
import { CircleAlert, Search, X } from 'lucide-react'
import { useState } from 'react'

import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'
import type { GraphQLIssue } from '#/lib/graphql/transport'
import { useTranslator } from '#/lib/i18n'
import { applyTimeRangePreset } from '../lib/audit-fields'
import {
  readAuditQueryHistory,
  withAuditQuery,
  writeAuditQueryHistory,
} from '../lib/audit-query-history'

const QUICK_RANGES = [
  { key: 'auditQuickRange15m', range: '[now-15m TO now]' },
  { key: 'auditQuickRange24h', range: '[now-24h TO now]' },
  { key: 'auditQuickRange7d', range: '[now-7d TO now]' },
  { key: 'auditQuickRange30d', range: '[now-30d TO now]' },
] as const

export interface AuditQueryBarProps {
  draftQuery: string
  onDraftChange: (nextQuery: string) => void
  onSearch: (nextQuery?: string) => void
  onClear: () => void
  fields: LuceneField[]
  locale: string
  timeZone: string
  disabled?: boolean
  /** Syntax error of the applied query (e.g. opened from a link); not sent to the server. */
  appliedQueryError?: string
  serverIssues?: ReadonlyArray<GraphQLIssue>
  requestId?: string
  traceId?: string
}

export function AuditQueryBar({
  draftQuery,
  onDraftChange,
  onSearch,
  onClear,
  fields,
  locale,
  timeZone,
  disabled = false,
  appliedQueryError,
  serverIssues,
  requestId,
  traceId,
}: AuditQueryBarProps) {
  const t = useTranslator()
  const [diagnostics, setDiagnostics] = useState<ComponentDiagnostic[]>([])
  const [submitRejected, setSubmitRejected] = useState(false)
  const [history, setHistory] = useState(readAuditQueryHistory)

  const blockingDiagnostic = diagnostics.find((item) => item.severity === 'error')
  const syntaxError =
    submitRejected && blockingDiagnostic ? blockingDiagnostic.message : appliedQueryError

  function submitValue(value: string) {
    const currentDiagnostics = getLuceneDiagnostics(value, fields, locale, undefined, {
      disallowUnknownFields: true,
    })
    setDiagnostics(currentDiagnostics)
    if (currentDiagnostics.some((item) => item.severity === 'error')) {
      setSubmitRejected(true)
      return
    }
    setSubmitRejected(false)
    if (value.trim()) {
      const nextHistory = withAuditQuery(history, value)
      setHistory(nextHistory)
      writeAuditQueryHistory(nextHistory)
    }
    onSearch(value)
  }

  return (
    <div className="space-y-2.5">
      <form
        className="flex flex-col gap-2 sm:flex-row sm:items-start"
        onSubmit={(event) => {
          event.preventDefault()
          submitValue(draftQuery)
        }}
      >
        <div className="min-w-0 flex-1">
          <LuceneInput
            id="audit-lucene-query"
            value={draftQuery}
            onChange={(nextValue) => {
              setSubmitRejected(false)
              onDraftChange(nextValue)
            }}
            onSubmit={(currentValue) => submitValue(currentValue)}
            onDiagnostics={setDiagnostics}
            // The rejection alert below already explains the error.
            diagnosticTooltip={!syntaxError}
            fields={fields}
            disallowUnknownFields
            locale={locale}
            timeZone={timeZone}
            placeholder={t('auditQueryPlaceholder')}
            ariaLabel={t('auditQueryLabel')}
            disabled={disabled}
            history={history}
            completionFooter={t('auditSyntaxHelp')}
          />
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Button type="submit" disabled={disabled}>
            <Search className="size-4" aria-hidden="true" />
            {t('auditSearchSubmit')}
          </Button>
          {draftQuery ? (
            <Button
              type="button"
              variant="ghost"
              disabled={disabled}
              onClick={() => {
                setSubmitRejected(false)
                onClear()
              }}
            >
              <X className="size-4" aria-hidden="true" />
              {t('auditSearchClear')}
            </Button>
          ) : null}
        </div>
      </form>

      <div className="flex flex-wrap items-center gap-1.5">
        {QUICK_RANGES.map((preset) => (
          <Button
            key={preset.range}
            type="button"
            size="sm"
            variant="outline"
            disabled={disabled}
            onClick={() => {
              const next = applyTimeRangePreset(draftQuery, preset.range)
              setSubmitRejected(false)
              onDraftChange(next)
              onSearch(next)
            }}
          >
            {t(preset.key)}
          </Button>
        ))}
      </div>

      {syntaxError ? (
        <Alert variant="destructive">
          <CircleAlert aria-hidden="true" />
          <AlertTitle>{t('auditInvalidQueryFeedback')}</AlertTitle>
          <AlertDescription>{syntaxError}</AlertDescription>
        </Alert>
      ) : null}

      {serverIssues && serverIssues.length > 0 ? (
        <Alert variant="destructive">
          <CircleAlert aria-hidden="true" />
          <AlertDescription className="space-y-2">
            <ErrorDetails issues={serverIssues} />
            <RequestCorrelation requestId={requestId} traceId={traceId} />
          </AlertDescription>
        </Alert>
      ) : null}
    </div>
  )
}
