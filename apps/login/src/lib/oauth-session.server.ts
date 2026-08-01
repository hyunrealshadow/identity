import { createHash } from 'node:crypto'
import { useSession } from '@tanstack/react-start/server'

import { loadClientCredentials } from './client-credentials.server'

const AUTH_SESSION_NAME = '__Host-identity.account'
const FLOW_SESSION_NAME = '__Host-identity.oauth'
const MFA_UI_SESSION_NAME = '__Host-identity.mfa-ui'
const AUTH_SESSION_MAX_AGE = 30 * 24 * 60 * 60
const FLOW_SESSION_MAX_AGE = 10 * 60
const MFA_UI_SESSION_MAX_AGE = 15 * 60

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
    otpauth_uri: string
    enrollment_token: string
  }
  recovery_codes?: Array<string>
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

export function deriveSessionPassword(clientSecret: string, purpose: string) {
  return createHash('sha256')
    .update('identity-account-cookie:v1\0', 'utf8')
    .update(purpose, 'utf8')
    .update('\0', 'utf8')
    .update(clientSecret, 'utf8')
    .digest('hex')
}

async function sessionPassword(purpose: string) {
  const { client_secret: clientSecret } = await loadClientCredentials()
  return deriveSessionPassword(clientSecret, purpose)
}
