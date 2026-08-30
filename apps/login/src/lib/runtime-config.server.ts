import { identityInternalJson } from './identity.server'

export interface RuntimeConfiguration {
  version: number
  oauth_client: {
    client_id: string
    client_secret: string
    generation: number
    expires_at: string
  }
  refresh_after: number
}

let snapshot: RuntimeConfiguration | undefined
let snapshotAt = 0
let refreshInFlight: Promise<RuntimeConfiguration> | undefined

const DEFAULT_REFRESH_AFTER_SECONDS = 60
const MAX_STALE_SECONDS = 5 * 60

function refreshAfterMs(config: RuntimeConfiguration) {
  const seconds = Number.isFinite(config.refresh_after)
    ? Math.max(1, config.refresh_after)
    : DEFAULT_REFRESH_AFTER_SECONDS
  return seconds * 1000
}

function snapshotStatus(config: RuntimeConfiguration) {
  const expiresAt = Date.parse(config.oauth_client.expires_at)
  if (!Number.isFinite(expiresAt)) return 'invalid-secret-expiry'
  if (expiresAt <= Date.now()) return 'secret-expired'
  if (Date.now() - snapshotAt > MAX_STALE_SECONDS * 1000) {
    return 'runtime-configuration-stale'
  }
  return undefined
}

async function refreshRuntimeConfiguration() {
  const value = await identityInternalJson<RuntimeConfiguration>(
    '/internal/workloads/self/runtime-configuration',
  )
  snapshot = value
  snapshotAt = Date.now()
  return value
}

export async function loadRuntimeConfiguration() {
  if (
    snapshot &&
    Date.now() - snapshotAt <
      Math.min(refreshAfterMs(snapshot), MAX_STALE_SECONDS * 1000)
  ) {
    return snapshot
  }
  if (refreshInFlight) return refreshInFlight
  refreshInFlight = refreshRuntimeConfiguration()
    .catch((error) => {
      if (!snapshot) throw error
      console.error('runtime configuration refresh failed', error)
      const reason = snapshotStatus(snapshot)
      if (reason) {
        throw new Error(`Runtime configuration is unusable: ${reason}`, {
          cause: error,
        })
      }
      return snapshot
    })
    .finally(() => {
      refreshInFlight = undefined
    })
  return refreshInFlight
}

export async function loadOAuthClient() {
  const config = await loadRuntimeConfiguration()
  const reason = snapshotStatus(config)
  if (reason) throw new Error(`Runtime configuration is unusable: ${reason}`)
  return {
    client_id: config.oauth_client.client_id,
    client_secret: config.oauth_client.client_secret,
  }
}

export function loadSessionSecret() {
  const secret = process.env.IDENTITY_LOGIN_SESSION_SECRET
  if (!secret) {
    throw new Error(
      'IDENTITY_LOGIN_SESSION_SECRET must be configured to seal login cookies',
    )
  }
  return secret
}

export function loadApplicationUrl() {
  return process.env.IDENTITY_PUBLIC_APP_URL ?? ''
}

const READY_THRESHOLD_SECONDS = 30 * 60

export async function runtimeConfigurationReadiness() {
  if (
    !snapshot ||
    Date.now() - snapshotAt >=
      Math.min(refreshAfterMs(snapshot), MAX_STALE_SECONDS * 1000)
  ) {
    try {
      await loadRuntimeConfiguration()
    } catch (error) {
      console.error('runtime configuration readiness check failed', error)
      // falls through to the snapshot-based assessment below
    }
  }
  if (!snapshot) return { ready: false, reason: 'no-runtime-configuration' }
  const snapshotReason = snapshotStatus(snapshot)
  if (snapshotReason) return { ready: false, reason: snapshotReason }
  const expiresAt = Date.parse(snapshot.oauth_client.expires_at)
  const remaining = expiresAt - Date.now()
  if (remaining < READY_THRESHOLD_SECONDS * 1000) {
    return { ready: false, reason: 'secret-near-expiry' }
  }
  return { ready: true }
}
