import { useState, type FormEvent, type ReactNode } from 'react'

import type { EnhancedNavigationResponse } from '#/lib/identity-types'

interface ProgressiveFormProps {
  action: string
  children: ReactNode
  className?: string
  enhancementErrorMessage: string
}

export function ProgressiveForm({
  action,
  children,
  className,
  enhancementErrorMessage,
}: ProgressiveFormProps) {
  const [isPending, setIsPending] = useState(false)
  const [enhancementError, setEnhancementError] = useState<string>()

  async function enhance(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setIsPending(true)
    setEnhancementError(undefined)

    const form = event.currentTarget
    const submitter = (event.nativeEvent as SubmitEvent).submitter
    const data = submitter
      ? new FormData(form, submitter)
      : new FormData(form)

    try {
      const response = await fetch(action, {
        method: 'POST',
        body: data,
        credentials: 'same-origin',
        headers: { 'x-enhanced-form': '1' },
      })
      const result = (await response.json()) as EnhancedNavigationResponse
      window.location.assign(result.redirect)
    } catch {
      setEnhancementError(enhancementErrorMessage)
      setIsPending(false)
    }
  }

  return (
    <form
      action={action}
      method="post"
      className={className}
      aria-busy={isPending}
      onSubmit={enhance}
    >
      {children}
      {enhancementError ? (
        <p className="mt-3 text-sm text-danger" role="alert">
          {enhancementError}
        </p>
      ) : null}
    </form>
  )
}
