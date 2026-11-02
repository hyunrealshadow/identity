import { createContext } from 'react'
import type { AuthSession } from '#/lib/auth/session'

/** Advisory live eligibility, bound to the session that loaded it; never a token grant. */
export const RequestableAccessContext = createContext<{
  session: AuthSession
  scopes: readonly string[]
} | null>(null)
