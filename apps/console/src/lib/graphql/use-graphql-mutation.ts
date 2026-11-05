import { useMutation } from '@tanstack/react-query'
import { useCallback } from 'react'

import type { DocumentSource, GraphQLResult } from '#/lib/graphql/transport'
import { useInvalidateOperations } from '#/lib/graphql/invalidate-operations'
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
 * A clean success marks the affected reads stale. The refetch is deliberately
 * not awaited: pages that already reload the current view afterwards share the
 * same in-flight request instead of issuing a second one.
 */
export function useGraphQLMutation(): GraphQLMutation {
  const request = useGraphQL()
  const invalidate = useInvalidateOperations()
  const { mutateAsync } = useMutation({
    mutationFn: async (input: MutationInput) => {
      const result = await request(
        input.document,
        input.variables,
        input.operationName,
      )
      if (
        input.invalidates &&
        input.invalidates.length > 0 &&
        !result.failure &&
        result.errors.length === 0
      ) {
        void invalidate(input.invalidates)
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
