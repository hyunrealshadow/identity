import { Button } from '@heroui/react'
import { RecoveryCodeList, RecoveryCodeTools } from './recovery-code-tools'
import type { translate } from '#/lib/i18n'

export function MfaRecoverySetup({ codes, t, onContinue }: { codes: Array<string>; t: (key: Parameters<typeof translate>[1]) => string; onContinue: () => void }) {
  return <section aria-label={t('accountRecoveryCodesTitle')}>
    <div>
      <h2 className="text-sm font-semibold">{t('accountRecoveryCodesTitle')}</h2>
      <p className="mt-1 text-sm leading-5">{t('accountMfaRecoveryStepDescription')}</p>
    </div>
    <div className="mt-4"><RecoveryCodeList codes={codes} copyLabel={t('accountRecoveryCodeCopy')} copiedLabel={t('accountRecoveryCodeCopied')} /></div>
    <div className="mt-4 flex flex-wrap items-center gap-2">
      <RecoveryCodeTools codes={codes} copyLabel={t('accountRecoveryCodesCopy')} copiedLabel={t('accountRecoveryCodesCopied')} printLabel={t('accountRecoveryCodesPrint')} downloadLabel={t('accountRecoveryCodesDownload')} />
      <Button type="button" className="ms-auto" onPress={onContinue}>{t('accountMfaContinue')}</Button>
    </div>
  </section>
}
