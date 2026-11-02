import { Button, Modal, Spinner, useOverlayState } from '@heroui/react'
import type { ReactNode } from 'react'

import { useTranslator, type MessageKey } from '#/lib/i18n'
import { rbacConflict } from '../lib/rbac-errors'
import type { useRelationMutation } from '../lib/relation-mutation'
import { RbacMutationFeedback } from './rbac-feedback'

export function RelationDialog({
  state,
  mutation,
  title,
  confirm,
  danger = false,
  size = 'lg',
  disabled = false,
  children,
  error,
  onSubmit,
  onReload,
  reloadPending,
  conflictTitleKey,
  conflictDescriptionKey,
  bodyClassName,
  dialogClassName,
}: {
  state: ReturnType<typeof useOverlayState>
  mutation: ReturnType<typeof useRelationMutation>
  title: string
  confirm: string
  danger?: boolean
  size?: 'md' | 'lg'
  disabled?: boolean
  children: ReactNode
  error?: string | null
  onSubmit: () => void
  onReload: () => void
  reloadPending: boolean
  conflictTitleKey?: MessageKey
  conflictDescriptionKey?: MessageKey
  bodyClassName?: string
  dialogClassName?: string
}) {
  const t = useTranslator()
  const { pending, feedback, setFeedback } = mutation
  return (
    <Modal state={state}>
      <Modal.Backdrop isDismissable={!pending}>
        <Modal.Container size={size} scroll="inside">
          <Modal.Dialog className={dialogClassName}>
            <Modal.CloseTrigger aria-label={t('close')} isDisabled={pending} />
            <Modal.Header>
              <Modal.Heading>{title}</Modal.Heading>
            </Modal.Header>
            <Modal.Body className={bodyClassName}>
              {children}
              {error ? (
                <p role="alert" className="mt-3 text-xs text-danger">
                  {error}
                </p>
              ) : null}
              {feedback ? (
                <div className="mt-4">
                  <RbacMutationFeedback
                    feedback={feedback}
                    conflictTitleKey={conflictTitleKey}
                    conflictDescriptionKey={conflictDescriptionKey}
                    reloadPending={reloadPending}
                    onReload={() => {
                      setFeedback(null)
                      onReload()
                    }}
                  />
                </div>
              ) : null}
            </Modal.Body>
            <Modal.Footer>
              <Button
                variant="secondary"
                isDisabled={pending}
                onPress={state.close}
              >
                {t('cancel')}
              </Button>
              <Button
                variant={danger ? 'danger' : 'primary'}
                isDisabled={
                  pending ||
                  reloadPending ||
                  disabled ||
                  Boolean(feedback && rbacConflict(feedback.errors).conflict)
                }
                onPress={onSubmit}
              >
                {pending ? (
                  <Spinner size="sm" aria-label={t('working')} />
                ) : null}
                {confirm}
              </Button>
            </Modal.Footer>
          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal>
  )
}
