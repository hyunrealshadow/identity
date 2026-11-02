import { createContext, useContext } from 'react'

import type { UserDetailState } from '../hooks/use-user-detail'

export const UserDetailContext = createContext<UserDetailState | null>(null)

export function useUserDetailContext() {
  const detail = useContext(UserDetailContext)
  if (!detail) throw new Error('User detail layout is required')
  return detail
}
