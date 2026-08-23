import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  identityJson: vi.fn(),
}))

vi.mock('./identity.server', () => ({
  identityJson: mocks.identityJson,
}))

beforeEach(() => {
  vi.resetModules()
  mocks.identityJson.mockReset()
})

describe('installation status cache', () => {
  it('shares one request across repeated and concurrent callers', async () => {
    mocks.identityJson.mockResolvedValue({ installed: true })
    const { cachedInstallationStatus } = await import('./installation-status.server')

    const first = cachedInstallationStatus()
    const second = cachedInstallationStatus()

    expect(first).toBe(second)
    await expect(Promise.all([first, second])).resolves.toEqual([
      { installed: true },
      { installed: true },
    ])
    expect(mocks.identityJson).toHaveBeenCalledOnce()
    expect(mocks.identityJson).toHaveBeenCalledWith('/installation/status')
  })

  it('clears a failed request so a later navigation can retry', async () => {
    mocks.identityJson
      .mockRejectedValueOnce(new Error('temporarily unavailable'))
      .mockResolvedValueOnce({ installed: true })
    const { cachedInstallationStatus } = await import('./installation-status.server')

    await expect(cachedInstallationStatus()).rejects.toThrow('temporarily unavailable')
    await expect(cachedInstallationStatus()).resolves.toEqual({ installed: true })
    expect(mocks.identityJson).toHaveBeenCalledTimes(2)
  })

  it('marks installation complete without another backend request', async () => {
    const { cachedInstallationStatus, markInstallationComplete } = await import('./installation-status.server')

    markInstallationComplete()

    await expect(cachedInstallationStatus()).resolves.toEqual({ installed: true })
    expect(mocks.identityJson).not.toHaveBeenCalled()
  })
})
