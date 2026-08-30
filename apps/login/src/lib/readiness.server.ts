import { cachedInstallationStatus } from './installation-status.server'
import { runtimeConfigurationReadiness } from './runtime-config.server'

export async function applicationReadiness() {
  try {
    const installation = await cachedInstallationStatus()
    if (!installation.installed) {
      return { ready: true, reason: 'installation-required' }
    }
  } catch (error) {
    console.error('installation status readiness check failed', error)
    return { ready: false, reason: 'installation-status-unavailable' }
  }

  return runtimeConfigurationReadiness()
}
