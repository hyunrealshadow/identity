import { useEffect, useState } from 'react'
import {
  ConsoleAuthorizationLabelsDocument,
  type ConsoleAuthorizationLabelsQuery,
} from '#/gql/graphql'
import { useGraphQL } from '#/lib/graphql/use-graphql'

/** Resolve each distinct label once, keeping every request inside the node lookup limit. */
export function useAuthorizationLabels(ids: readonly string[]) {
  const request = useGraphQL()
  const key = JSON.stringify(ids)
  const [state, setState] = useState<{
    key: string
    nodes: ConsoleAuthorizationLabelsQuery['nodes']
    failed: boolean
  }>({ key: '', nodes: [], failed: false })
  useEffect(() => {
    let cancelled = false
    const selected: string[] = JSON.parse(key)
    void (async () => {
      const nodes: ConsoleAuthorizationLabelsQuery['nodes'] = []
      let failed = false
      try {
        for (let offset = 0; offset < selected.length; offset += 100) {
          const result = await request(
            ConsoleAuthorizationLabelsDocument,
            { ids: selected.slice(offset, offset + 100) },
            'ConsoleAuthorizationLabels',
          )
          if (cancelled) return
          nodes.push(...(result.data?.nodes ?? []))
          failed ||= result.data === null || result.errors.length > 0
        }
      } catch {
        failed = true
      }
      if (!cancelled) setState({ key, nodes, failed })
    })()
    return () => {
      cancelled = true
    }
  }, [key, request])
  return state.key === key ? state : { nodes: [], failed: false }
}
