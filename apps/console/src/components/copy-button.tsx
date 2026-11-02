import { Button } from '@heroui/react'
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
        isIconOnly
        size="sm"
        variant="ghost"
        className="size-6 min-w-6 shrink-0"
        aria-label={t('copyValue', { label })}
        isDisabled={pending}
        onPress={async () => {
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
        <span className="ml-1 text-xs text-danger" aria-hidden="true">
          {feedback}
        </span>
      ) : null}
    </span>
  )
}
