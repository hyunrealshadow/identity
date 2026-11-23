import { Skeleton } from '@identity/ui/components/skeleton'
import { Spinner } from '@identity/ui/components/spinner'
import { CircleAlert } from 'lucide-react'
import { useEffect, useState } from 'react'

import {
  ConsoleEmailTemplatePreviewDocument,
  type ConsoleEmailTemplatePreviewQuery,
  type ConsoleEmailTemplatePreviewQueryVariables,
  type EmailTemplateKind,
} from '#/generated/graphql'
import { fieldErrorMap } from '#/lib/graphql/transport'
import { useGraphQL } from '#/lib/graphql/use-graphql'
import { useTranslator } from '#/lib/i18n'
import type { EmailTemplateContentDraft } from '../lib/email-form'

type Rendered = NonNullable<ConsoleEmailTemplatePreviewQuery['emailTemplatePreview']>

/** Wait for typing to pause before rendering again. */
const PREVIEW_DELAY_MS = 400

type PreviewState =
  | { status: 'loading'; rendered?: Rendered }
  | { status: 'ready'; rendered: Rendered }
  | { status: 'error'; message: string; part?: string; rendered?: Rendered }

/**
 * The draft rendered by the server with sample values. The HTML body is shown
 * in a sandboxed frame that may not run scripts, submit forms or navigate.
 */
export function EmailPreview({
  kind,
  locale,
  content,
  enabled,
}: {
  kind: EmailTemplateKind
  locale: string
  content: EmailTemplateContentDraft
  enabled: boolean
}) {
  const t = useTranslator()
  const request = useGraphQL()
  const [view, setView] = useState<'html' | 'text'>('html')
  const [state, setState] = useState<PreviewState>({ status: 'loading' })
  const { subject, html, text } = content

  useEffect(() => {
    if (!enabled) return
    const controller = new AbortController()
    setState((current) => ({ status: 'loading', rendered: current.rendered }))
    const timer = window.setTimeout(() => {
      void request<ConsoleEmailTemplatePreviewQuery, ConsoleEmailTemplatePreviewQueryVariables>(
        ConsoleEmailTemplatePreviewDocument,
        { input: { kind, locale, content: { subject, html, text } } },
        'ConsoleEmailTemplatePreview',
        { signal: controller.signal },
      )
        .then((result) => {
          if (controller.signal.aborted) return
          const rendered = result.data?.emailTemplatePreview
          if (rendered) {
            setState({ status: 'ready', rendered })
            return
          }
          const [path, message] = Object.entries(fieldErrorMap(result.errors))[0] ?? []
          setState((current) => ({
            status: 'error',
            message: message ?? result.errors[0]?.message ?? t('settingsEmailPreviewFailed'),
            part: path?.split('.').at(-1),
            rendered: current.rendered,
          }))
        })
        .catch(() => {
          if (controller.signal.aborted) return
          setState((current) => ({
            status: 'error',
            message: t('settingsEmailPreviewFailed'),
            rendered: current.rendered,
          }))
        })
    }, PREVIEW_DELAY_MS)
    return () => {
      window.clearTimeout(timer)
      controller.abort()
    }
  }, [enabled, kind, locale, subject, html, text, request, t])

  const rendered = state.rendered
  const partLabel =
    state.status === 'error' && state.part
      ? {
          subject: t('settingsEmailTemplateSubject'),
          html: t('settingsEmailTemplateHtml'),
          text: t('settingsEmailTemplateText'),
        }[state.part]
      : undefined

  return (
    <section aria-label={t('settingsEmailPreview')} className="xl:sticky xl:top-4">
      <div className="mb-2 flex min-h-8 items-center justify-between gap-3 px-1">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold">{t('settingsEmailPreview')}</h3>
          {enabled && state.status === 'loading' && rendered ? (
            <Spinner className="size-3.5 text-muted-foreground" aria-label={t('settingsEmailPreviewUpdating')} />
          ) : null}
        </div>
        <div role="tablist" aria-label={t('settingsEmailPreviewFormat')} className="flex rounded-lg bg-muted p-0.5">
          {(['html', 'text'] as const).map((option) => (
            <button
              key={option}
              type="button"
              role="tab"
              aria-selected={view === option}
              onClick={() => setView(option)}
              className={
                'rounded-md px-2.5 py-1 text-xs font-medium ' +
                (view === option ? 'bg-background shadow-xs' : 'text-muted-foreground')
              }
            >
              {option === 'html' ? t('settingsEmailPreviewHtml') : t('settingsEmailPreviewText')}
            </button>
          ))}
        </div>
      </div>
      <div className="console-card overflow-hidden rounded-xl border border-border bg-card">
        {!enabled ? (
          <p className="px-5 py-4 text-sm text-muted-foreground">{t('settingsEmailPreviewUnavailable')}</p>
        ) : (
          <>
            {state.status === 'error' ? (
              <div role="alert" className="flex gap-2 border-b border-border bg-destructive/5 px-5 py-3 text-xs leading-5 text-destructive">
                <CircleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
                <p className="min-w-0 break-words">
                  {partLabel ? <span className="font-semibold">{partLabel}: </span> : null}
                  {state.message}
                </p>
              </div>
            ) : null}
            <div className="border-b border-border px-5 py-3">
              <p className="text-xs text-muted-foreground">{t('settingsEmailTemplateSubject')}</p>
              {rendered ? (
                <p className="mt-0.5 break-words text-sm font-medium">{rendered.subject}</p>
              ) : (
                <Skeleton className="mt-1.5 h-4 w-2/3 rounded-lg" />
              )}
            </div>
            {rendered ? (
              view === 'html' ? (
                <iframe
                  title={t('settingsEmailPreviewHtml')}
                  srcDoc={rendered.html}
                  sandbox=""
                  referrerPolicy="no-referrer"
                  className="block h-[32rem] w-full bg-white"
                />
              ) : (
                <pre className="h-[32rem] overflow-auto whitespace-pre-wrap break-words px-5 py-4 font-mono text-xs leading-5">
                  {rendered.text}
                </pre>
              )
            ) : (
              <Skeleton className="h-[32rem] w-full rounded-none" />
            )}
          </>
        )}
      </div>
    </section>
  )
}
