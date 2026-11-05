import { createContext, useContext } from 'react'
import type { ConsoleRoleQuery } from '#/generated/graphql'
import type { ConsoleQueryState } from '#/lib/graphql/use-console-query'

export const RoleDetailContext =
  createContext<ConsoleQueryState<ConsoleRoleQuery> | null>(null)
export function useRoleDetailContext() {
  const value = useContext(RoleDetailContext)
  if (!value) throw new Error('Role detail context is missing')
  return value
}
