import { identityInternalJson } from './identity.server'
import type { InstallationStatusResponse } from './identity-types'

const UNINSTALLED_CACHE_MS = 5_000

interface InstallationStatusCache {
  expiresAt: number
  promise: Promise<InstallationStatusResponse>
}

let installationStatus: InstallationStatusCache | undefined

export function cachedInstallationStatus() {
  if (!installationStatus || Date.now() >= installationStatus.expiresAt) {
    const entry: InstallationStatusCache = {
      expiresAt: Number.POSITIVE_INFINITY,
      promise: Promise.resolve({ installed: false }),
    }
    entry.promise = identityInternalJson<InstallationStatusResponse>(
      '/internal/installation/status',
    )
      .then((status) => {
        if (installationStatus === entry && !status.installed) {
          entry.expiresAt = Date.now() + UNINSTALLED_CACHE_MS
        }
        return status
      })
      .catch((error) => {
        if (installationStatus === entry) installationStatus = undefined
        throw error
      })
    installationStatus = entry
  }

  return installationStatus.promise
}

export function markInstallationComplete() {
  installationStatus = {
    expiresAt: Number.POSITIVE_INFINITY,
    promise: Promise.resolve({ installed: true }),
  }
}
