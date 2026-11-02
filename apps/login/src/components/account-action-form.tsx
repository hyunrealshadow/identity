import { Alert } from '@heroui/react'
import { useRouter } from '@tanstack/react-router'
import { useState, type FormEvent, type ReactNode } from 'react'

import { useAccountReauth } from '#/components/reauthentication-popup'

interface AccountActionFormProps {
  action: string
  children: ReactNode
  className?: string
  requestFailedMessage: string
  onSuccess?: (action: string) => void
}

export function AccountActionForm({
  action,
  children,
  className,
  requestFailedMessage,
  onSuccess,
}: AccountActionFormProps) {
  const router = useRouter()
  const { requestReauth, executeAction } = useAccountReauth()
  const [isPending, setIsPending] = useState(false)
  const [requestError, setRequestError] = useState<string>()

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (isPending) return

    const form = event.currentTarget
    const submitter = (event.nativeEvent as SubmitEvent).submitter
    const formData = submitter
      ? new FormData(form, submitter)
      : new FormData(form)
    const submittedAction = String(formData.get('action') ?? action)
    const values = Object.fromEntries(
      Array.from(formData.entries(), ([name, value]) => [
        name,
        typeof value === 'string' ? value : value.name,
      ]),
    )

    setIsPending(true)
    setRequestError(undefined)
    try {
      const result = await executeAction({ action: submittedAction, values })
      if (result.localError) { setRequestError(result.localError); return }
      if (result.reauth) {
        // Reauthentication resumes the intended dialog through its continuation.
        // The originally submitted sensitive mutation is never replayed.
        requestReauth(result.reauth)
        return
      }
      if (result.redirect) {
        window.location.assign(result.redirect)
        return
      }
      await router.invalidate()
      if (result.ok) onSuccess?.(submittedAction)
    } catch {
      setRequestError(requestFailedMessage)
    } finally {
      setIsPending(false)
    }
  }

  return (
    <form className={className} aria-busy={isPending} onSubmit={submit}>
      <fieldset className="contents" disabled={isPending}>
        {children}
      </fieldset>
      {requestError ? (
        <Alert status="danger" className="mt-3">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Description>{requestError}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
    </form>
  )
}
