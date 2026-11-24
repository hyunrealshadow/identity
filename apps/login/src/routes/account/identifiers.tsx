import { Button } from '@identity/ui/components/button'
import { Separator } from '@identity/ui/components/separator'
import { createFileRoute } from '@tanstack/react-router'

import { AccountActionForm } from '#/components/account-action-form'
import { AccountDialog } from '#/components/account-dialog'
import { useDialogState } from '#/components/use-dialog-state'
import { PageHeading, ProfileField, SettingsCard, SettingsRow } from '#/components/account-settings'
import { translate, type Locale } from '#/lib/i18n'
import { useAccount } from './route'

export const Route = createFileRoute('/account/identifiers')({
  component: IdentifiersPage,
})

function IdentifiersPage() {
  const { locale, data, flash } = useAccount()
  const account = data.account
  const verification = data.accountEmailVerification
  const pending = verification.pending
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
          <Separator className="my-5" />
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
            action={
              <div className="flex flex-wrap gap-2">
                {!account.emailVerified && verification.available && !pending ? (
                  <AccountActionForm
                    action="send-email-verification"
                    requestFailedMessage={t('accountRequestFailed')}
                  >
                    <Button type="submit" variant="outline">{t('accountSendVerificationEmail')}</Button>
                  </AccountActionForm>
                ) : null}
                <EmailModal account={account} flash={flash} t={t} verifies={verification.available} />
              </div>
            }
          />
          {pending ? (
            <PendingVerification
              email={pending.email}
              changesEmail={pending.changesEmail}
              locale={locale}
              t={t}
            />
          ) : null}
      </SettingsCard>
    </>
  )
}

type Account = ReturnType<typeof useAccount>['data']['account']
type Flash = ReturnType<typeof useAccount>['flash']
type Translator = (key: Parameters<typeof translate>[1]) => string

/** The verification link in progress: resend it, or withdraw a change. */
function PendingVerification({
  email,
  changesEmail,
  locale,
  t,
}: {
  email: string
  changesEmail: boolean
  locale: Locale
  t: Translator
}) {
  return (
    <div className="mt-4 flex flex-col gap-3 rounded-md border border-border bg-muted/40 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
      <p className="text-sm leading-5 text-muted-foreground">
        {translate(
          locale,
          changesEmail ? 'accountEmailChangePending' : 'accountEmailVerificationPending',
          { email },
        )}
      </p>
      <div className="flex shrink-0 flex-wrap gap-2">
        {changesEmail ? (
          <AccountActionForm
            action="cancel-email-verification"
            requestFailedMessage={t('accountRequestFailed')}
          >
            <Button type="submit" variant="ghost" size="sm">{t('accountCancelEmailChange')}</Button>
          </AccountActionForm>
        ) : null}
        <AccountActionForm
          action="send-email-verification"
          requestFailedMessage={t('accountRequestFailed')}
        >
          <Button type="submit" variant="outline" size="sm">{t('accountResendVerificationEmail')}</Button>
        </AccountActionForm>
      </div>
    </div>
  )
}

function UsernameModal({ account, flash, t }: { account: Account; flash: Flash; t: Translator }) {
  const modal = useDialogState()
  return (
    <>
      <Button variant="outline" onClick={modal.open}>{t('accountChangeUsername')}</Button>
      <AccountDialog state={modal} title={t('accountChangeUsername')} closeLabel={t('close')} className="sm:max-w-md">
        <AccountActionForm
          action="update-username"
          requestFailedMessage={t('accountRequestFailed')}
          onSuccess={modal.close}
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
      </AccountDialog>
    </>
  )
}

function EmailModal({
  account,
  flash,
  t,
  verifies,
}: {
  account: Account
  flash: Flash
  t: Translator
  verifies: boolean
}) {
  const modal = useDialogState()
  return (
    <>
      <Button variant="outline" onClick={modal.open}>{t('accountChangeEmail')}</Button>
      <AccountDialog state={modal} title={t('accountChangeEmail')} closeLabel={t('close')} className="sm:max-w-md">
        <AccountActionForm
          action="update-email"
          requestFailedMessage={t('accountRequestFailed')}
          onSuccess={modal.close}
          className="grid gap-4"
        >
          <p className="text-sm leading-5 text-muted-foreground">
            {t(verifies ? 'accountEmailChangeVerifyHint' : 'accountEmailChangeImmediateHint')}
          </p>
          <ProfileField
            name="email"
            label={t('accountEmail')}
            value={account.email}
            error={flash.fields?.email}
            required
            type="email"
          />
          <Button type="submit" className="justify-self-end">
            {t(verifies ? 'accountSendVerificationEmail' : 'accountSaveEmail')}
          </Button>
        </AccountActionForm>
      </AccountDialog>
    </>
  )
}
