import { identityJson } from './identity.server'
import type { InstallationStatusResponse } from './identity-types'

let installationStatus: Promise<InstallationStatusResponse> | undefined

export function cachedInstallationStatus() {
  if (!installationStatus) {
    installationStatus = identityJson<InstallationStatusResponse>(
      '/installation/status',
    ).catch((error) => {
      installationStatus = undefined
      throw error
    })
  }

  return installationStatus
}

export function markInstallationComplete() {
  installationStatus = Promise.resolve({ installed: true })
}
