import { useTranslator } from '#/lib/i18n'

export function RequestCorrelation({
  requestId,
  traceId,
}: {
  requestId?: string
  traceId?: string
}) {
  const t = useTranslator()
  if (!requestId && !traceId) return null

  return (
    <dl className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs text-muted">
      {requestId ? (
        <div className="flex min-w-0 items-center gap-1.5">
          <dt className="shrink-0">{t('requestId')}</dt>
          <dd className="truncate font-mono text-foreground">{requestId}</dd>
        </div>
      ) : null}
      {traceId ? (
        <div className="flex min-w-0 items-center gap-1.5">
          <dt className="shrink-0">{t('traceId')}</dt>
          <dd className="truncate font-mono text-foreground">{traceId}</dd>
        </div>
      ) : null}
    </dl>
  )
}
