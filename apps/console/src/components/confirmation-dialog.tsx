import { Button, Modal, Spinner, useOverlayState } from '@heroui/react'
import type { ReactNode } from 'react'

import { useTranslator } from '#/lib/i18n'

export type ConfirmationState = ReturnType<typeof useOverlayState>

export function ConfirmationDialog({
  state,
  title,
  description,
  children,
  confirmLabel,
  cancelLabel,
  pending = false,
  destructive = false,
  onConfirm,
}: {
  state: ConfirmationState
  title: string
  description?: string
  children?: ReactNode
  confirmLabel?: string
  cancelLabel?: string
  pending?: boolean
  destructive?: boolean
  onConfirm: () => void
}) {
  const t = useTranslator()

  return (
    <Modal state={state}>
      <Modal.Backdrop isDismissable={!pending}>
        <Modal.Container size="md">
          <Modal.Dialog>
            {({ close }) => (
              <>
                <Modal.CloseTrigger aria-label={t('close')} isDisabled={pending} />
                <Modal.Header>
                  <Modal.Heading>{title}</Modal.Heading>
                </Modal.Header>
                <Modal.Body>
                  {description ? <p className="text-sm leading-6 text-muted">{description}</p> : null}
                  {children ? <div className="mt-3 text-sm leading-6">{children}</div> : null}
                </Modal.Body>
                <Modal.Footer>
                  <Button
                    type="button"
                    variant="secondary"
                    isDisabled={pending}
                    onPress={close}
                  >
                    {cancelLabel ?? t('cancel')}
                  </Button>
                  <Button
                    type="button"
                    variant={destructive ? 'danger' : 'primary'}
                    isDisabled={pending}
                    onPress={onConfirm}
                  >
                    {pending ? <Spinner size="sm" aria-label={t('working')} /> : null}
                    {confirmLabel ?? t('confirm')}
                  </Button>
                </Modal.Footer>
              </>
            )}
          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal>
  )
}
