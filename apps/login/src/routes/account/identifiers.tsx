import { Button, Modal } from '@heroui/react'
import { createFileRoute } from '@tanstack/react-router'

import { AccountActionForm } from '#/components/account-action-form'
import { PageHeading, ProfileField, SettingsCard, SettingsRow } from '#/components/account-settings'
import { translate } from '#/lib/i18n'
import { useAccount } from './route'

export const Route = createFileRoute('/account/identifiers')({
  component: IdentifiersPage,
})

function IdentifiersPage() {
  const { locale, data, flash } = useAccount()
  const account = data.viewer.account
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)

  return (
    <>
      <PageHeading
        title={t('accountIdentifiers')}
        description={t('accountIdentifiersDescription')}
      />
      <SettingsCard
        title={t('accountSignInIdentifiers')}
      >
          <SettingsRow
            title={t('accountUsername')}
            description={account.username}
            action={<UsernameModal account={account} flash={flash} t={t} />}
          />
          <div className="my-5 border-t border-separator" />
          <SettingsRow
            title={t('accountEmail')}
            description={account.email}
            detail={
              <span className={account.emailVerified ? 'text-success' : 'text-warning'}>
                {account.emailVerified
                  ? t('accountEmailVerified')
                  : t('accountEmailUnverified')}
              </span>
            }
            action={<EmailModal account={account} flash={flash} t={t} />}
          />
      </SettingsCard>
    </>
  )
}

type Account = ReturnType<typeof useAccount>['data']['viewer']['account']
type Flash = ReturnType<typeof useAccount>['flash']
type Translator = (key: Parameters<typeof translate>[1]) => string

function UsernameModal({ account, flash, t }: { account: Account; flash: Flash; t: Translator }) {
  return (
    <Modal>
      <Modal.Trigger>
        <Button variant="secondary">{t('accountChangeUsername')}</Button>
      </Modal.Trigger>
      <Modal.Backdrop isDismissable={false}>
        <Modal.Container size="md">
          <Modal.Dialog>
            {({ close }) => (
              <>
                <Modal.CloseTrigger aria-label={t('close')} />
                <Modal.Header>
                  <Modal.Heading>{t('accountChangeUsername')}</Modal.Heading>
                </Modal.Header>
                <Modal.Body>
                  <AccountActionForm
                    action="update-username"
                    requestFailedMessage={t('accountRequestFailed')}
                    onSuccess={close}
                    className="grid gap-4"
                  >
                    <ProfileField
                      name="username"
                      label={t('accountUsername')}
                      value={account.username}
                      error={flash.fields?.username}
                      required
                    />
                    <Button type="submit" className="justify-self-end">
                      {t('accountSaveUsername')}
                    </Button>
                  </AccountActionForm>
                </Modal.Body>
              </>
            )}
          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal>
  )
}

function EmailModal({ account, flash, t }: { account: Account; flash: Flash; t: Translator }) {
  return (
    <Modal>
      <Modal.Trigger>
        <Button variant="secondary">{t('accountChangeEmail')}</Button>
      </Modal.Trigger>
      <Modal.Backdrop isDismissable={false}>
        <Modal.Container size="md">
          <Modal.Dialog>
            {({ close }) => (
              <>
                <Modal.CloseTrigger aria-label={t('close')} />
                <Modal.Header>
                  <Modal.Heading>{t('accountChangeEmail')}</Modal.Heading>
                </Modal.Header>
                <Modal.Body>
                  <AccountActionForm
                    action="update-email"
                    requestFailedMessage={t('accountRequestFailed')}
                    onSuccess={close}
                    className="grid gap-4"
                  >
                    <ProfileField
                      name="email"
                      label={t('accountEmail')}
                      value={account.email}
                      error={flash.fields?.email}
                      required
                      type="email"
                    />
                    <Button type="submit" className="justify-self-end">
                      {t('accountSaveEmail')}
                    </Button>
                  </AccountActionForm>
                </Modal.Body>
              </>
            )}
          </Modal.Dialog>
        </Modal.Container>
      </Modal.Backdrop>
    </Modal>
  )
}
