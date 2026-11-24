import { Button } from '@identity/ui/components/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@identity/ui/components/dialog'
import { Field, FieldError, FieldLabel } from '@identity/ui/components/field'
import { Input } from '@identity/ui/components/input'
import type { OverlayState } from '@identity/ui/hooks/use-overlay-state'
import { Send } from 'lucide-react'
import { useEffect, useId, useState } from 'react'

import type { EmailTemplateKind } from '#/generated/graphql'
import { useAuth } from '#/lib/auth/context'
import { fieldErrorMap } from '#/lib/graphql/transport'
import { useLocale, useTranslator } from '#/lib/i18n'
import { toast } from '#/lib/toast'
import { RbacMutationFeedback } from '#/modules/user-management/components/rbac-feedback'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'
import { mutationFeedback, networkFeedback } from '../../settings/lib/feedback'
import { useEmailMutations } from '../hooks/email-mutations'
import type { EmailTemplateContentDraft } from '../lib/email-form'

export interface SendTestEmailTemplatePayload {
  kind: EmailTemplateKind
  locale: string | null
  content: EmailTemplateContentDraft
}

/**
 * Prompts for a recipient and sends either the generic delivery check or a
 * rendered email template draft. Mount outside any surrounding `<form>`.
 */
export function SendTestEmailDialog({
  state,
  template,
  title,
  description,
}: {
  state: OverlayState
  template?: SendTestEmailTemplatePayload | null
  title?: string
  description?: string
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const { claims } = useAuth()
  const mutations = useEmailMutations()
  const inputId = useId()
  const errorId = useId()
  const [recipient, setRecipient] = useState('')
  const [error, setError] = useState<string>()
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)
  const [pending, setPending] = useState(false)

  useEffect(() => {
    if (state.isOpen) {
      setRecipient((current) => current || claims?.email || '')
    } else {
      setError(undefined)
      setFeedback(null)
    }
  }, [state.isOpen, claims?.email])

  async function send() {
    if (pending) return
    const trimmed = recipient.trim()
    if (!/^[^\s@]+@[^\s@]+$/u.test(trimmed)) {
      setError(t('settingsEmailInvalidAddress'))
      return
    }
    setPending(true)
    setFeedback(null)
    try {
      const result = await mutations.sendTestEmail({
        recipient: trimmed,
        locale,
        template: template ?? null,
      })
      if (!result.data?.sendTestEmail?.sent) {
        const fields = fieldErrorMap(result.errors)
        if (fields.recipient) setError(fields.recipient)
        else setFeedback(mutationFeedback(result, 'missing_send_test_email_payload'))
        return
      }
      state.close()
      toast.success(t('settingsEmailTestSent', { recipient: trimmed }))
    } catch {
      setFeedback(networkFeedback('send_test_email_request_failed'))
    } finally {
      setPending(false)
    }
  }

  return (
    <Dialog
      open={state.isOpen}
      onOpenChange={(open) => {
        if (!open && pending) return
        state.setOpen(open)
      }}
    >
      <DialogContent showCloseButton={!pending} closeLabel={t('close')}>
        <form
          noValidate
          aria-busy={pending}
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault()
            void send()
          }}
        >
          <DialogHeader>
            <DialogTitle>{title ?? t('settingsEmailTestSection')}</DialogTitle>
            <DialogDescription>{description ?? t('settingsEmailTestHint')}</DialogDescription>
          </DialogHeader>
          {feedback ? <RbacMutationFeedback feedback={feedback} /> : null}
          <Field data-invalid={error ? true : undefined}>
            <FieldLabel htmlFor={inputId}>{t('settingsEmailTestRecipient')}</FieldLabel>
            <Input
              id={inputId}
              name="recipient"
              type="email"
              value={recipient}
              onChange={(event) => {
                setRecipient(event.currentTarget.value)
                setError(undefined)
                setFeedback(null)
              }}
              placeholder="you@example.com"
              autoComplete="email"
              spellCheck={false}
              disabled={pending}
              aria-invalid={error ? true : undefined}
              aria-describedby={error ? errorId : undefined}
            />
            {error ? <FieldError id={errorId}>{error}</FieldError> : null}
          </Field>
          <DialogFooter>
            <Button type="button" variant="outline" disabled={pending} onClick={state.close}>
              {t('cancel')}
            </Button>
            <Button type="submit" loading={pending}>
              {pending ? null : <Send className="size-4" aria-hidden="true" />}
              {t('settingsEmailTestSend')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
