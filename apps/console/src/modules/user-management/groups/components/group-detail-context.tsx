import { createContext, useContext } from 'react'
import type { ConsoleGroupQuery } from '#/generated/graphql'
import type { ConsoleQueryState } from '#/lib/graphql/use-console-query'

export const GroupDetailContext =
  createContext<ConsoleQueryState<ConsoleGroupQuery> | null>(null)
export function useGroupDetailContext() {
  const value = useContext(GroupDetailContext)
  if (!value) throw new Error('Group detail context is missing')
  return value
}
