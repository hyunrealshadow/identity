import { useMutation } from '@tanstack/react-query'
import { useCallback } from 'react'

import type { DocumentSource, GraphQLResult } from '#/lib/graphql/transport'
import { useInvalidateOperations } from '#/lib/graphql/invalidate-operations'
import { usePatchVersionedEntities } from '#/lib/graphql/patch-versioned-entities'
import { useGraphQL } from '#/lib/graphql/use-graphql'
import { operationNameOf, type AnyDocument } from './query-keys'

/** One mutation through the shared request path; returns the full result. */
export type GraphQLMutation = <TData, TVariables>(
  document: string | DocumentSource<TData, TVariables>,
  variables: TVariables,
  /** Read documents this write invalidates once it succeeds cleanly. */
  invalidates?: readonly AnyDocument[],
) => Promise<GraphQLResult<TData>>

interface MutationInput {
  document: AnyDocument
  variables: unknown
  invalidates?: readonly AnyDocument[]
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
    mutationFn: (input: MutationInput) =>
      request(input.document, input.variables, operationNameOf(input.document)),
    // GraphQL failures resolve as data, so only a clean result touches the
    // cache. Mutation-level callbacks finish before `mutateAsync` resolves.
    onSuccess: (result, input) => {
      if (result.failure || result.errors.length > 0) return
      patch(input.document, result.data)
      if (input.invalidates?.length) void invalidate(input.invalidates)
    },
  })

  return useCallback(
    <TData, TVariables>(
      document: string | DocumentSource<TData, TVariables>,
      variables: TVariables,
      invalidates?: readonly AnyDocument[],
    ) =>
      mutateAsync({ document, variables, invalidates }) as Promise<
        GraphQLResult<TData>
      >,
    [mutateAsync],
  )
}
