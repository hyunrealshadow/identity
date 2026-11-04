import { afterEach, describe, expect, it } from 'vitest'

import {
  applyApplicationOrigins,
  configuredApplicationOrigin,
  configuredApplicationUrl,
  trustedHttpsOrigin,
} from './application-origins.server'

afterEach(() => applyApplicationOrigins(undefined))

describe('configured application origins', () => {
  it('uses installed origins independently', () => {
    applyApplicationOrigins({
      domain: 'https://issuer.example/',
      login_domain: 'https://login.example',
      console_domain: 'https://console.example:3100/console',
    })
    expect(configuredApplicationOrigin('domain')).toBe('https://issuer.example')
    expect(configuredApplicationOrigin('login_domain')).toBe(
      'https://login.example',
    )
    expect(configuredApplicationOrigin('console_domain')).toBe(
      'https://console.example:3100',
    )
    expect(configuredApplicationUrl('console_domain')).toBe('https://console.example:3100/console')
  })

  it('rejects unsafe application addresses', () => {
    for (const value of ['https://bad.example/?q', 'http://unsafe.example', 'https://u:p@bad.example', '*']) {
      expect(trustedHttpsOrigin(value)).toBeUndefined()
    }
    expect(trustedHttpsOrigin('https://console.example/')).toBe('https://console.example')
  })
})
