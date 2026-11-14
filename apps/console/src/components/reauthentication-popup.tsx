import { Button } from '@identity/ui/components/button'

import type { PopupReauthenticationPrompt } from '#/lib/auth/popup-reauthentication'
import { authErrorKey } from '#/lib/auth/messages'
import { useTranslator } from '#/lib/i18n'

/**
 * A compact, non-modal notice shown only when a popup could not open or the
 * verification failed. The workspace stays visible and usable behind it.
 */
export function ReauthenticationPopup({
  prompt,
  onContinue,
  onFallback,
  onCancel,
}: {
  prompt: PopupReauthenticationPrompt
  onContinue: () => void
  onFallback: () => void
  onCancel: () => void
}) {
  const t = useTranslator()
  if (prompt.phase !== 'blocked' && prompt.phase !== 'failed') return null

  const blocked = prompt.phase === 'blocked'

  return (
    <aside
      aria-live="polite"
      className="fixed bottom-4 right-4 z-50 w-[min(22rem,calc(100vw-2rem))] rounded-lg border border-border bg-card p-4 text-foreground shadow-lg"
    >
      <p className="text-sm font-medium">
        {t(blocked ? 'authPopupBlockedTitle' : 'authPopupFailedTitle')}
      </p>
      <p className="mt-1 text-xs leading-5 text-muted-foreground">
        {t(
          blocked ? 'authPopupBlockedDescription' : 'authPopupFailedDescription',
        )}
      </p>
      {!blocked && prompt.errorCode ? (
        <p className="mt-1 text-xs leading-5 text-muted-foreground">
          {t(authErrorKey(prompt.errorCode))}
        </p>
      ) : null}
      <div className="mt-3 flex flex-wrap gap-2">
        <Button
          type="button"
          size="sm"
          variant="default"
          onClick={onContinue}
        >
          {t(blocked ? 'authPopupContinue' : 'retry')}
        </Button>
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={onFallback}
        >
          {t('authPopupContinueInTab')}
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={onCancel}>
          {t('close')}
        </Button>
      </div>
    </aside>
  )
}
