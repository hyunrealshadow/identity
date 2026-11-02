import { describe, expect, it } from 'vitest'

import { accountInitials } from './account-avatar'

describe('accountInitials', () => {
  it('uses two uppercase initials across account surfaces', () => {
    expect(accountInitials(' admin')).toBe('AD')
    expect(accountInitials('Ada Lovelace')).toBe('AL')
  })

  it('handles Unicode names and empty display names', () => {
    expect(accountInitials('张三')).toBe('张三')
    expect(accountInitials('')).toBe('?')
  })
})
