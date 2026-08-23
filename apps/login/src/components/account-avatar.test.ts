import { describe, expect, it } from 'vitest'

import { accountInitial } from './account-avatar'

describe('accountInitial', () => {
  it('uses the same uppercase fallback initial across account surfaces', () => {
    expect(accountInitial(' admin')).toBe('A')
  })

  it('handles Unicode names and empty display names', () => {
    expect(accountInitial('张三')).toBe('张')
    expect(accountInitial('')).toBe('?')
  })
})
