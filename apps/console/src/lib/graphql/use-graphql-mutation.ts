import { useMutation } from '@tanstack/react-query'
import { useCallback } from 'react'

import type { DocumentSource, GraphQLResult } from '#/lib/graphql/transport'
import { useInvalidateOperations } from '#/lib/graphql/invalidate-operations'
import { usePatchVersionedEntities } from '#/lib/graphql/patch-versioned-entities'
import { useGraphQL } from '#/lib/graphql/use-graphql'

/** One mutation through the shared request path; returns the full result. */
export type GraphQLMutation = <TData, TVariables>(
  document: string | DocumentSource<TData, TVariables>,
  variables: TVariables,
  operationName?: string,
  /** Read operations this write invalidates once it succeeds cleanly. */
  invalidates?: readonly string[],
) => Promise<GraphQLResult<TData>>

interface MutationInput {
  document: string | DocumentSource<unknown, unknown>
  variables: unknown
  operationName?: string
  invalidates?: readonly string[]
}

/**
 * Mutations run through TanStack Query's mutation cache so a component can
 * observe pending state, while callers keep the existing "await the result"
 * contract used across the console.
 *
 * A clean success first applies the returned version to the cached detail
 * reads, then marks the affected reads stale. The refetch is deliberately not
 * awaited: pages that already reload the current view afterwards share the
 * same in-flight request instead of issuing a second one.
 */
export function useGraphQLMutation(): GraphQLMutation {
  const request = useGraphQL()
  const invalidate = useInvalidateOperations()
  const patch = usePatchVersionedEntities()
  const { mutateAsync } = useMutation({
    mutationFn: async (input: MutationInput) => {
      const result = await request(
        input.document,
        input.variables,
        input.operationName,
      )
      if (!result.failure && result.errors.length === 0) {
        patch(input.operationName, result.data)
        if (input.invalidates && input.invalidates.length > 0) {
          void invalidate(input.invalidates)
        }
      }
      return result
    },
  })

  return useCallback(
    <TData, TVariables>(
      document: string | DocumentSource<TData, TVariables>,
      variables: TVariables,
      operationName?: string,
      invalidates?: readonly string[],
    ) =>
      mutateAsync({
        document: document as unknown as MutationInput['document'],
        variables,
        operationName,
        invalidates,
      }) as Promise<GraphQLResult<TData>>,
    [mutateAsync],
  )
}
