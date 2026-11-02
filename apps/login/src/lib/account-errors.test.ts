import { describe, expect, it } from 'vitest'

import { graphqlFieldErrors, htmlFieldName } from './account-errors'

describe('account GraphQL field errors', () => {
  it('maps GraphQL input names to HTML form names', () => {
    expect(htmlFieldName('newPassword')).toBe('new_password')
    expect(htmlFieldName('zoneInfo')).toBe('zone_info')
    expect(htmlFieldName('code')).toBe('code')
  })

  it('collects all field messages from GraphQL errors', () => {
    expect(
      graphqlFieldErrors([
        {
          extensions: {
            fields: [
              { field: 'newPassword', message: 'Use at least 12 characters' },
              { field: 'zoneInfo', message: 'Choose a valid time zone' },
            ],
          },
        },
      ]),
    ).toEqual({
      new_password: 'Use at least 12 characters',
      zone_info: 'Choose a valid time zone',
    })
  })
})
