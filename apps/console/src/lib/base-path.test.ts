import { afterEach, describe, expect, it, vi } from 'vitest'

async function load() {
  vi.stubEnv('BASE_URL', '/console/')
  vi.resetModules()
  return import('./base-path')
}

describe('basePathRewrite', () => {
  afterEach(() => {
    vi.unstubAllEnvs()
    vi.resetModules()
  })

  it('writes the Console home without a trailing slash', async () => {
    const { basePathRewrite } = await load()
    const output = (path: string) =>
      (basePathRewrite.output!({ url: new URL(path, 'https://console.example') }) as URL).pathname
    expect(output('/')).toBe('/console')
    expect(output('/users/one')).toBe('/console/users/one')
  })

  it('reads both home forms and nested routes below the prefix', async () => {
    const { basePathRewrite } = await load()
    const input = (path: string) =>
      (basePathRewrite.input!({ url: new URL(path, 'https://console.example') }) as URL).pathname
    expect(input('/console')).toBe('/')
    expect(input('/console/')).toBe('/')
    expect(input('/console/users/one')).toBe('/users/one')
    expect(input('/console-other')).toBe('/console-other')
  })
})
