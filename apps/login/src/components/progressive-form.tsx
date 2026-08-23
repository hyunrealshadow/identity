import { Alert } from '@heroui/react'
import { useState, type FormEvent, type ReactNode } from 'react'

import { FormPendingContext } from '#/components/submit-button'

import type { EnhancedNavigationResponse } from '#/lib/identity-types'

interface ProgressiveFormProps {
  action: string
  children: ReactNode
  className?: string
  enhancementErrorMessage: string
  noValidate?: boolean
}

export function ProgressiveForm({
  action,
  children,
  className,
  enhancementErrorMessage,
  noValidate = false,
}: ProgressiveFormProps) {
  // `undefined` = idle, otherwise the `value` of the clicked submitter
  // (null when the submitter carries no value attribute).
  const [pendingSubmitter, setPendingSubmitter] = useState<string | null>()
  const [enhancementError, setEnhancementError] = useState<string>()

  async function enhance(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setEnhancementError(undefined)

    const form = event.currentTarget
    const submitter = (event.nativeEvent as SubmitEvent).submitter
    const data = submitter
      ? new FormData(form, submitter)
      : new FormData(form)
    setPendingSubmitter(submitter?.getAttribute('value') ?? null)

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
      setPendingSubmitter(undefined)
      setEnhancementError(enhancementErrorMessage)
    }
  }

  const isPending = pendingSubmitter !== undefined

  return (
    <form
      action={action}
      method="post"
      className={className}
      aria-busy={isPending}
      noValidate={noValidate}
      onSubmit={enhance}
    >
      <FormPendingContext
        value={{ isPending, submitter: pendingSubmitter ?? null }}
      >
        {children}
      </FormPendingContext>
      {enhancementError ? (
        <Alert
          status="danger"
          className="auth-alert mt-4"
        >
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Description>{enhancementError}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
    </form>
  )
}
