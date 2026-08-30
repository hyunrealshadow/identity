import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  cachedInstallationStatus: vi.fn(),
  runtimeConfigurationReadiness: vi.fn(),
}))

vi.mock('./installation-status.server', () => ({
  cachedInstallationStatus: mocks.cachedInstallationStatus,
}))

vi.mock('./runtime-config.server', () => ({
  runtimeConfigurationReadiness: mocks.runtimeConfigurationReadiness,
}))

beforeEach(() => {
  vi.clearAllMocks()
})

describe('applicationReadiness', () => {
  it('is ready to serve the installer before installation completes', async () => {
    mocks.cachedInstallationStatus.mockResolvedValue({ installed: false })
    const { applicationReadiness } = await import('./readiness.server')

    await expect(applicationReadiness()).resolves.toEqual({
      ready: true,
      reason: 'installation-required',
    })
    expect(mocks.runtimeConfigurationReadiness).not.toHaveBeenCalled()
  })

  it('checks runtime credentials after installation', async () => {
    mocks.cachedInstallationStatus.mockResolvedValue({ installed: true })
    mocks.runtimeConfigurationReadiness.mockResolvedValue({ ready: true })
    const { applicationReadiness } = await import('./readiness.server')

    await expect(applicationReadiness()).resolves.toEqual({ ready: true })
    expect(mocks.runtimeConfigurationReadiness).toHaveBeenCalledOnce()
  })

  it('is unready when the installation status cannot be checked', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    mocks.cachedInstallationStatus.mockRejectedValue(new Error('unavailable'))
    const { applicationReadiness } = await import('./readiness.server')

    await expect(applicationReadiness()).resolves.toEqual({
      ready: false,
      reason: 'installation-status-unavailable',
    })
  })
})
