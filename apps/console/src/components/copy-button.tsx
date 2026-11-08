import { Button } from '@identity/ui/components/button'
import { Check, Copy } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslator } from '#/lib/i18n'

export function CopyButton({ value, label }: { value: string; label: string }) {
  const t = useTranslator()
  const [status, setStatus] = useState<'idle' | 'copied' | 'failed'>('idle')
  const [pending, setPending] = useState(false)
  useEffect(() => setStatus('idle'), [value])
  useEffect(() => {
    if (status === 'idle') return
    const timer = window.setTimeout(() => setStatus('idle'), 2500)
    return () => window.clearTimeout(timer)
  }, [status])
  const feedback =
    status === 'copied'
      ? t('valueCopied')
      : status === 'failed'
        ? t('valueCopyFailed')
        : ''
  return (
    <span
      className="inline-flex shrink-0"
      title={feedback || t('copyValue', { label })}
    >
      <Button
        type="button"
        size="icon-xs"
        variant="ghost"
        className="shrink-0"
        aria-label={t('copyValue', { label })}
        disabled={pending}
        onClick={async () => {
          setPending(true)
          try {
            await navigator.clipboard.writeText(value)
            setStatus('copied')
          } catch {
            setStatus('failed')
          } finally {
            setPending(false)
          }
        }}
      >
        {status === 'copied' ? (
          <Check className="size-3.5" aria-hidden="true" />
        ) : (
          <Copy className="size-3.5" aria-hidden="true" />
        )}
      </Button>
      <span role="status" className="sr-only">
        {feedback}
      </span>
      {status === 'failed' ? (
        <span className="ml-1 text-xs text-destructive" aria-hidden="true">
          {feedback}
        </span>
      ) : null}
    </span>
  )
}
