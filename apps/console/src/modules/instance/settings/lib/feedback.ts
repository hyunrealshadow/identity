import type { GraphQLResult } from '#/lib/graphql/transport'
import type { RbacFeedbackState } from '#/modules/user-management/lib/rbac-errors'

/** Feedback for a mutation that returned no payload. */
export function mutationFeedback(
  result: Pick<
    GraphQLResult<unknown>,
    'errors' | 'failure' | 'stepUp' | 'requestId' | 'traceId' | 'forbidden'
  >,
  code: string,
): RbacFeedbackState {
  return {
    errors: result.errors,
    failure: result.failure ?? {
      kind: 'invalid_response',
      code,
      requestId: result.requestId,
      traceId: result.traceId,
    },
    stepUp: result.stepUp,
    requestId: result.requestId,
    traceId: result.traceId,
    forbidden: result.forbidden,
  }
}

export function networkFeedback(code: string): RbacFeedbackState {
  return { errors: [], failure: { kind: 'network', code }, forbidden: false }
}
