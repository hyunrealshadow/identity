import { useEffect, useRef } from 'react'

import { AsyncState } from '#/components/async-state'
import { useAuth } from '#/lib/auth/context'
import type { GraphQLStepUp } from '#/lib/graphql/transport'
import { useTranslator } from '#/lib/i18n'

/**
 * Shared entry point for pages that render a step-up
 * outcome. It does not own a warning or a button: the central coordinator
 * performs one coalesced redirect, so concurrent panels cannot start multiple
 * authorization requests.
 */
export function StepUpPanel(props: {
  stepUp: GraphQLStepUp
  hideDetails?: boolean
  description?: string
  note?: string
}) {
  const t = useTranslator()
  const { requireReauthentication, reauthenticationPopup } = useAuth()
  const requested = useRef(false)

  useEffect(() => {
    if (props.stepUp.recoveryManaged || requested.current) return
    requested.current = true
    void requireReauthentication(props.stepUp, { reason: 'step_up' })
  }, [props.stepUp, requireReauthentication])

  // Request outcomes are retained alongside drafts. Their recovery is owned by
  // useGraphQL, so remounting one must neither reopen a completed popup nor keep
  // a loading banner after completion or cancellation.
  if (props.stepUp.recoveryManaged && !reauthenticationPopup) return null

  return (
    <AsyncState
      kind="loading"
      compact
      title={t('authReauthenticatingTitle')}
      description={t('authReauthenticatingDescription')}
    />
  )
}
