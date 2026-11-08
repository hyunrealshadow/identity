import { createContext, useContext, useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react'

import { ErrorAlert } from '#/components/form-alert'
import { FormPendingContext } from '#/components/submit-button'

import type { EnhancedNavigationResponse } from '#/lib/identity-types'

type ValidationErrors = Record<string, string>

/** Server field errors of the enclosing ProgressiveForm, cleared per edited field */
export const FormValidationContext = createContext<ValidationErrors | undefined>(undefined)

export function useFieldValidationError(name: string | undefined) {
  const errors = useContext(FormValidationContext)
  return name ? errors?.[name] : undefined
}

interface ProgressiveFormProps {
  action: string
  children: ReactNode
  className?: string
  enhancementErrorMessage: string
  noValidate?: boolean
  validationErrors?: ValidationErrors
}

/**
 * A native POST form that keeps working without JavaScript. After hydration it
 * submits through `fetch` so the clicked button can show progress, then follows
 * the server-selected navigation.
 */
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
    <form
      action={action}
      method="post"
      className={className}
      aria-busy={isPending}
      data-enhanced={enhanced ? 'true' : 'false'}
      noValidate={noValidate}
      onInput={clearEditedFieldError}
      onChange={clearEditedFieldError}
      onSubmit={enhance}
    >
      <FormValidationContext value={currentValidationErrors}>
        <FormPendingContext
          value={{ isPending, submitter: pendingSubmitter ?? null }}
        >
          {children}
        </FormPendingContext>
      </FormValidationContext>
      {enhancementError ? (
        <ErrorAlert message={enhancementError} className="mt-4" />
      ) : null}
    </form>
  )
}
