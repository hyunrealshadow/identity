import {
  LuceneInput,
  getLuceneDiagnostics,
  type ComponentDiagnostic,
  type LuceneField,
  type LuceneInputHandle,
} from '@identity/lucene-input'
import { Alert, AlertDescription, AlertTitle } from '@identity/ui/components/alert'
import { Button } from '@identity/ui/components/button'
import { CircleAlert, Search, X } from 'lucide-react'
import { useRef, useState } from 'react'

import { ErrorDetails } from '#/components/error-details'
import { RequestCorrelation } from '#/components/request-correlation'
import type { GraphQLIssue } from '#/lib/graphql/transport'
import { useTranslator } from '#/lib/i18n'
import { AUDIT_DIAGNOSTIC_OPTIONS, AUDIT_DISABLED_SYNTAX, applyTimeRangePreset } from '../lib/audit-fields'
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

  const input = useRef<LuceneInputHandle>(null)
  const errorCount = diagnostics.filter((item) => item.severity === 'error').length

  function submitValue(value: string) {
    const currentDiagnostics = getLuceneDiagnostics(
      value,
      fields,
      locale,
      undefined,
      AUDIT_DIAGNOSTIC_OPTIONS,
    )
    setDiagnostics(currentDiagnostics)
    if (currentDiagnostics.some((item) => item.severity === 'error')) {
      // The input's popover lists the errors and the caret goes to the first.
      setSubmitRejected(true)
      input.current?.revealProblems()
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
            ref={input}
            id="audit-lucene-query"
            value={draftQuery}
            onChange={(nextValue) => {
              setSubmitRejected(false)
              onDraftChange(nextValue)
            }}
            onSubmit={(currentValue) => submitValue(currentValue)}
            onDiagnostics={setDiagnostics}
            fields={fields}
            disallowUnknownFields
            disabledSyntax={AUDIT_DISABLED_SYNTAX}
            locale={locale}
            timeZone={timeZone}
            placeholder={t('auditQueryPlaceholder')}
            ariaLabel={t('auditQueryLabel')}
            disabled={disabled}
            history={history}
            completionFooter={t('auditSyntaxHelp')}
            trailing={
              draftQuery || (submitRejected && errorCount > 0) ? (
                <>
                  {submitRejected && errorCount > 0 ? (
                    <Button
                      type="button"
                      variant="ghost"
                      size="xs"
                      className="text-destructive hover:text-destructive"
                      onClick={() => input.current?.revealProblems()}
                    >
                      <CircleAlert aria-hidden="true" />
                      <span role="status">{t('auditInvalidQueryCount', { count: errorCount })}</span>
                    </Button>
                  ) : null}
                  {draftQuery ? (
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-xs"
                      aria-label={t('auditSearchClear')}
                      title={t('auditSearchClear')}
                      disabled={disabled}
                      onClick={() => {
                        setSubmitRejected(false)
                        onClear()
                      }}
                    >
                      <X aria-hidden="true" />
                    </Button>
                  ) : null}
                </>
              ) : null
            }
          />
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Button type="submit" disabled={disabled}>
            <Search className="size-4" aria-hidden="true" />
            {t('auditSearchSubmit')}
          </Button>
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

      {appliedQueryError ? (
        <Alert variant="destructive">
          <CircleAlert aria-hidden="true" />
          <AlertTitle>{t('auditInvalidQueryFeedback')}</AlertTitle>
          <AlertDescription>{appliedQueryError}</AlertDescription>
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
