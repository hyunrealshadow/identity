import { Button } from '@identity/ui/components/button'
import { cn } from '@identity/ui/lib/utils'
import { Check, Copy } from 'lucide-react'
import { useEffect, useState, type ReactNode } from 'react'
import { useTranslator } from '#/lib/i18n'

export function CopyButton({
  value,
  label,
  className,
}: {
  value: string
  label: string
  className?: string
}) {
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
        className={cn('shrink-0', className)}
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

/**
 * A copyable value and its copy button on one tinted surface, so everything a
 * person can copy reads the same across Console. `inline` hugs the value for
 * table cells and headers; `block` fills its row for values that stand alone.
 * `children` replaces the displayed text, for example with a link, while the
 * copied text is always `value`.
 */
export function CopyableValue({
  value,
  label,
  children,
  layout = 'inline',
  size = 'xs',
  wrap = 'break',
  className,
  valueClassName,
}: {
  value: string
  label: string
  children?: ReactNode
  layout?: 'inline' | 'block'
  size?: 'xs' | 'sm'
  /** `truncate` keeps one line and shows the full value on hover. */
  wrap?: 'break' | 'truncate'
  className?: string
  valueClassName?: string
}) {
  return (
    <span
      className={cn(
        'max-w-full min-w-0 items-center gap-1 rounded-md bg-muted py-0.5 pr-0.5 pl-2 text-foreground',
        layout === 'block' ? 'flex w-full py-1.5 pl-3' : 'inline-flex',
        className,
      )}
    >
      <code
        className={cn(
          // IDs and hashes have no descenders; trimming the text box to cap
          // height and baseline centres the glyphs rather than the line box;
          // the padding restores breathing room when the value wraps.
          'min-w-0 flex-1 py-1 font-mono [text-box:trim-both_cap_alphabetic]',
          size === 'sm' ? 'text-sm' : 'text-xs',
          wrap === 'truncate' ? 'truncate' : 'break-all',
          valueClassName,
        )}
        title={wrap === 'truncate' ? value : undefined}
      >
        {children ?? value}
      </code>
      <CopyButton
        value={value}
        label={label}
        className="self-start not-disabled:hover:bg-background dark:not-disabled:hover:bg-background/60"
      />
    </span>
  )
}
