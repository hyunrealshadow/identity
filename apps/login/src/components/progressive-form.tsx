import { Alert, Form } from '@heroui/react'
import { useEffect, useMemo, useState, type ComponentProps, type FormEvent, type ReactNode } from 'react'

import { FormPendingContext } from '#/components/submit-button'

import type { EnhancedNavigationResponse } from '#/lib/identity-types'

interface ProgressiveFormProps {
  action: string
  children: ReactNode
  className?: string
  enhancementErrorMessage: string
  noValidate?: boolean
  validationErrors?: ComponentProps<typeof Form>['validationErrors']
}

export function ProgressiveForm({
  action,
  children,
  className,
  enhancementErrorMessage,
  noValidate = false,
  validationErrors,
}: ProgressiveFormProps) {
  // `undefined` = idle, otherwise the `value` of the clicked submitter
  // (null when the submitter carries no value attribute).
  const [pendingSubmitter, setPendingSubmitter] = useState<string | null>()
  const [enhancementError, setEnhancementError] = useState<string>()
  const [enhanced, setEnhanced] = useState(false)
  const [editedValidation, setEditedValidation] = useState(() => ({
    source: validationErrors,
    fields: new Set<string>(),
  }))
  const currentValidationErrors = useMemo(() => {
    if (!validationErrors || editedValidation.source !== validationErrors) return validationErrors
    return Object.fromEntries(Object.entries(validationErrors).filter(
      ([name]) => !editedValidation.fields.has(name),
    ))
  }, [editedValidation, validationErrors])

  function clearEditedFieldError(event: FormEvent<HTMLFormElement>) {
    const name = (event.target as { name?: string }).name
    if (!name || !validationErrors || !(name in validationErrors)) return
    // Let the field update its value before removing its previous server error.
    setEditedValidation((current) => ({
      source: validationErrors,
      fields: new Set([
        ...(current.source === validationErrors ? current.fields : []),
        name,
      ]),
    }))
  }

  // The server-rendered fields can be visible before React has attached their
  // handlers. Expose completion so browser clients can safely fill the form.
  useEffect(() => setEnhanced(true), [])

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
    <Form
      action={action}
      method="post"
      className={className}
      aria-busy={isPending}
      data-enhanced={enhanced ? 'true' : 'false'}
      validationBehavior={noValidate ? 'aria' : 'native'}
      validationErrors={currentValidationErrors}
      render={(props) => <form {...props} onChange={clearEditedFieldError} />}
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
    </Form>
  )
}
