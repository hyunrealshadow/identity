import { createContext, useContext } from 'react'

import type { AccountAccessContext } from '#/modules/account/lib/account-operations'
import type { ThemePreference } from '#/lib/appearance'
import type { Locale } from '#/lib/i18n'

export interface AccountSession {
  id: string
  status: string
  current: boolean
  deviceName?: string
  deviceType?: string
  osName?: string
  osVersion?: string
  browserName?: string
  browserVersion?: string
  ipAddress?: string
  lastActiveAt?: string
  createdAt: string
}

export interface AccountSessionConnection {
  pageInfo?: {
    hasPreviousPage: boolean
    hasNextPage: boolean
    startCursor?: string | null
    endCursor?: string | null
  }
  edges: Array<{ cursor?: string; node: AccountSession }>
}

export interface AccountData {
  passkeys: Array<{ id: string; name: string }>
  account: {
    id: string
    username: string
    email: string
    emailVerified: boolean
    givenName?: string
    familyName?: string
    nickname?: string
    picture?: string
    website?: string
    birthdate?: string
    zoneInfo?: string
    locale?: string
    theme?: string
    createdAt: string
  }
  sessions: AccountSessionConnection
  security: {
    mfaEnabled: boolean
    totpEnabled: boolean
    recoveryCodesRemaining: number
    preferredMfaMethod: 'passkey' | 'otp'
  }
  effectivePermissions: {
    requestableScopes: string[]
    effectiveScopes: string[]
  }
  accountEmailVerification: {
    available: boolean
    pending: {
      email: string
      changesEmail: boolean
      sentAt: string
      expiresAt: string
      resendAvailableAt: string
    } | null
  }
}

export interface AccountFlash {
  message?: string
  error?: string
  fields?: Record<string, string>
}

export interface AccountMfaUiState {
  enrollment?: {
    secret: string
    otp_auth_uri: string
    enrollment_token: string
    recovery_codes: Array<string>
  }
  recoveryCodes?: Array<string>
}

export interface AccountContextValue {
  locale: Locale
  theme: ThemePreference
  data: AccountData
  access?: AccountAccessContext
  consoleUrl?: string
  mfa: AccountMfaUiState
  flash: AccountFlash
}

const AccountContext = createContext<AccountContextValue | null>(null)

export const AccountProvider = AccountContext.Provider

export function useAccount(): AccountContextValue {
  const value = useContext(AccountContext)
  if (!value) {
    throw new Error('useAccount must be used inside AccountLayout')
  }
  return value
}
