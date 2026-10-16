import { Button, Input, Label, TextField } from '@heroui/react'
import { useRouter } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'

import { SettingsRow } from './account-settings'
import { translate, type Locale } from '#/lib/i18n'
import { createPasskey, passkeysSupported, type PasskeyOptions } from '#/lib/passkey'
import { passkeyAccountAction } from '#/lib/passkey-account.server'

const action = createServerFn({ method: 'POST' })
  .validator((data: Parameters<typeof passkeyAccountAction>[0]) => data)
  .handler(async ({ data }) => {
    const { options, ...result } = await passkeyAccountAction(data)
    return { ...result, optionsJson: options ? JSON.stringify(options) : undefined }
  })

export function PasskeySettings({ locale, keys }: { locale: Locale; keys: Array<{ id: string; name: string }> }) {
  const router = useRouter()
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [supported, setSupported] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => setSupported(passkeysSupported()), [])
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)

  async function run(id?: string) {
    setBusy(true)
    setError('')
    try {
      let result = await action({ data: id ? { action: 'delete', id } : { action: 'begin' } })
      if (result.optionsJson) {
        const options = JSON.parse(result.optionsJson) as PasskeyOptions
        const credential = await createPasskey(options)
        result = await action({ data: { action: 'finish', id: options.challenge_id, name: name.trim(), credential: JSON.stringify(credential) } })
      }
      if (result.redirect) { window.location.assign(result.redirect); return }
      if (result.error) { setError(result.error); return }
      setName('')
      await router.invalidate()
    } catch (error) {
      setError(error instanceof Error && error.name === 'NotAllowedError' ? t('passkeyCancelled') : t('passkeyFailed'))
    } finally { setBusy(false) }
  }

  return <section aria-label={t('passkeys')}>
    <h3 className="text-sm font-semibold">{t('passkeys')}</h3>
    <p className="mt-1 text-sm leading-5 text-muted">{t('passkeysDescription')}</p>
    <div className="mt-4 space-y-4">
      {keys.map((key) => <SettingsRow key={key.id} title={key.name} action={
        <Button variant="danger-soft" isDisabled={busy} onPress={() => {
          if (window.confirm(t('passkeyDeleteConfirm'))) void run(key.id)
        }}>{t('passkeyDelete')}</Button>
      } />)}
      {!keys.length ? <p className="text-sm text-muted">{t('passkeyEmpty')}</p> : null}
      <TextField name="passkey_name" value={name} onChange={setName} maxLength={100}>
        <Label>{t('passkeyName')}</Label><Input placeholder={t('passkeyNamePlaceholder')} />
      </TextField>
      <Button variant="secondary" isDisabled={!supported || busy || !name.trim()} isPending={busy} onPress={() => void run()}>{t('passkeyAdd')}</Button>
      <p className="no-js-only text-xs text-muted">{t('passkeyRequiresJavascript')}</p>
      {!supported ? <p className="js-only text-xs text-muted">{t('passkeyUnsupported')}</p> : null}
      {error ? <p role="alert" className="text-sm text-danger">{error}</p> : null}
    </div>
  </section>
}
