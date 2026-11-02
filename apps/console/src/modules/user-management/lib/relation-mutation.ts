import { useRef, useState } from 'react'

import type { GraphQLResult } from '#/lib/graphql/transport'
import type { RbacFeedbackState } from './rbac-errors'

/** Shared request state; commands, CAS targets and success effects stay in the feature. */
export function useRelationMutation() {
  const locked = useRef(false)
  const [pending, setPending] = useState(false)
  const [feedback, setFeedback] = useState<RbacFeedbackState | null>(null)

  async function run(action: () => Promise<void>, networkCode: string) {
    if (locked.current) return
    locked.current = true
    setPending(true)
    setFeedback(null)
    try {
      await action()
    } catch {
      setFeedback({
        errors: [],
        failure: { kind: 'network', code: networkCode },
        forbidden: false,
      })
    } finally {
      locked.current = false
      setPending(false)
    }
  }

  function accept<T>(
    result: GraphQLResult<unknown>,
    payload: T,
    missingCode: string,
  ): payload is NonNullable<T> {
    if (payload !== null && payload !== undefined) return true
    setFeedback({
      errors: result.errors,
      failure: result.failure ?? {
        kind: 'invalid_response',
        code: missingCode,
        requestId: result.requestId,
        traceId: result.traceId,
      },
      stepUp: result.stepUp,
      forbidden: result.forbidden,
      requestId: result.requestId,
      traceId: result.traceId,
    })
    return false
  }

  return { pending, feedback, setFeedback, run, accept }
}
