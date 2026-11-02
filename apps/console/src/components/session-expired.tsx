import { Button } from '@heroui/react'

import { AsyncState } from '#/components/async-state'
import { useAuth } from '#/lib/auth/context'
import { currentReturnTo } from '#/lib/auth/return-to'
import { useTranslator } from '#/lib/i18n'

export function SessionExpired() {
  const t = useTranslator()
  const { signIn } = useAuth()

  return (
    <div className="mx-auto max-w-2xl p-4 sm:p-6">
      <AsyncState
        kind="unauthorized"
        title={t('sessionExpiredTitle')}
        description={t('sessionExpiredDescription')}
        action={
          <Button onPress={() => void signIn({ returnTo: currentReturnTo() })}>
            {t('sessionExpiredAction')}
          </Button>
        }
      />
    </div>
  )
}
