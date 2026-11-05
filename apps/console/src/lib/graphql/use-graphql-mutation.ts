import { useMutation } from '@tanstack/react-query'
import { useCallback } from 'react'

import type { DocumentSource, GraphQLResult } from '#/lib/graphql/transport'
import { useGraphQL } from '#/lib/graphql/use-graphql'

/** One mutation through the shared request path; returns the full result. */
export type GraphQLMutation = <TData, TVariables>(
  document: string | DocumentSource<TData, TVariables>,
  variables: TVariables,
  operationName?: string,
) => Promise<GraphQLResult<TData>>

interface MutationInput {
  document: string | DocumentSource<unknown, unknown>
  variables: unknown
  operationName?: string
}

/**
 * Mutations run through TanStack Query's mutation cache so a component can
 * observe pending state and future invalidations, while callers keep the
 * existing "await the result" contract used across the console.
 */
export function useGraphQLMutation(): GraphQLMutation {
  const request = useGraphQL()
  const { mutateAsync } = useMutation({
    mutationFn: (input: MutationInput) =>
      request(input.document, input.variables, input.operationName),
  })

  return useCallback(
    <TData, TVariables>(
      document: string | DocumentSource<TData, TVariables>,
      variables: TVariables,
      operationName?: string,
    ) =>
      mutateAsync({
        document: document as unknown as MutationInput['document'],
        variables,
        operationName,
      }) as Promise<GraphQLResult<TData>>,
    [mutateAsync],
  )
}
