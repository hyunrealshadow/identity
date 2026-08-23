import { createHash } from 'node:crypto'
import { useSession } from '@tanstack/react-start/server'

import { loadClientCredentials } from './client-credentials.server'

const AUTH_SESSION_NAME = '__Host-login.account'
const FLOW_SESSION_NAME = '__Host-login.oauth'
const MFA_UI_SESSION_NAME = '__Host-login.mfa-ui'
const ACCOUNT_FLASH_SESSION_NAME = '__Host-login.flash'
const AUTH_SESSION_MAX_AGE = 30 * 24 * 60 * 60
const FLOW_SESSION_MAX_AGE = 10 * 60
const MFA_UI_SESSION_MAX_AGE = 15 * 60
const ACCOUNT_FLASH_SESSION_MAX_AGE = 5 * 60

export interface OAuthFlowSession {
  state: string
  verifier: string
  mode: 'signin' | 'reauth'
  return_to: string
  reauth_purpose?: 'password' | 'account' | 'mfa'
}

export interface OAuthTokenSession {
  access_token: string
  refresh_token?: string
  id_token?: string
  expires_at: number
  elevated_access_token?: string
  elevated_expires_at?: number
}

export interface MfaUiSession {
  mfa_enrollment?: {
    secret: string
    otp_auth_uri: string
    enrollment_token: string
    recovery_codes: Array<string>
  }
}

export interface AccountFlashSession {
  message?: 'saved' | 'reauthenticated'
  error?: string
  fields?: Record<string, string>
}

export async function useAuthorizationSession() {
  return useSession<OAuthTokenSession>({
    name: AUTH_SESSION_NAME,
    password: await sessionPassword('authorization'),
    maxAge: AUTH_SESSION_MAX_AGE,
    sessionHeader: false,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: AUTH_SESSION_MAX_AGE,
    },
  })
}

export async function useOAuthFlowSession() {
  return useSession<OAuthFlowSession>({
    name: FLOW_SESSION_NAME,
    password: await sessionPassword('oauth-flow'),
    maxAge: FLOW_SESSION_MAX_AGE,
    sessionHeader: false,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: FLOW_SESSION_MAX_AGE,
    },
  })
}

export async function useMfaUiSession() {
  return useSession<MfaUiSession>({
    name: MFA_UI_SESSION_NAME,
    password: await sessionPassword('mfa-ui'),
    maxAge: MFA_UI_SESSION_MAX_AGE,
    sessionHeader: false,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: MFA_UI_SESSION_MAX_AGE,
    },
  })
}

export async function useAccountFlashSession() {
  return useSession<AccountFlashSession>({
    name: ACCOUNT_FLASH_SESSION_NAME,
    password: await sessionPassword('account-flash'),
    maxAge: ACCOUNT_FLASH_SESSION_MAX_AGE,
    sessionHeader: false,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: ACCOUNT_FLASH_SESSION_MAX_AGE,
    },
  })
}

export async function storeAccountFlash(value: AccountFlashSession) {
  await (await useAccountFlashSession()).update(value)
}

export async function consumeAccountFlash() {
  const session = await useAccountFlashSession()
  const value: AccountFlashSession = {
    message: session.data.message,
    error: session.data.error,
    fields: session.data.fields,
  }
  await session.clear()
  return value
}

export function deriveSessionPassword(clientSecret: string, purpose: string) {
  return createHash('sha256')
    .update('login.cookie:v1\0', 'utf8')
    .update(purpose, 'utf8')
    .update('\0', 'utf8')
    .update(clientSecret, 'utf8')
    .digest('hex')
}

async function sessionPassword(purpose: string) {
  const { client_secret: clientSecret } = await loadClientCredentials()
  return deriveSessionPassword(clientSecret, purpose)
}
