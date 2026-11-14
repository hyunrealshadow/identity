import { describe, expect, it } from 'vitest'
import { formatCalendarDate, formatDateTime } from '#/lib/format'
import { resolveTimeZone, startOfZonedDate } from '#/lib/time-zone'
import { usersQueryVariables, validateUsersSearch } from '#/modules/user-management/users/lib/users-search'

describe('user time zone', () => {
  it('uses the saved IANA zone, with browser fallback for unset and unsupported values', () => {
    expect(resolveTimeZone('America/New_York', 'Asia/Shanghai')).toBe('America/New_York')
    expect(resolveTimeZone(null, 'Asia/Shanghai')).toBe('Asia/Shanghai')
    expect(resolveTimeZone('Invalid/Zone', 'Asia/Shanghai')).toBe('Asia/Shanghai')
    expect(resolveTimeZone('+02:00', 'Asia/Shanghai')).toBe('Asia/Shanghai')
    expect(resolveTimeZone(null, 'Invalid/Zone')).toBe('UTC')
  })
  it('formats the same instant on the correct local date on either side of UTC', () => {
    expect(formatDateTime('2026-01-01T00:30:00Z', 'en-US', 'America/Los_Angeles')).toBe('Dec 31, 2025, 4:30 PM')
    expect(formatDateTime('2026-01-01T00:30:00Z', 'en-US', 'Asia/Shanghai')).toBe('Jan 1, 2026, 8:30 AM')
    expect(formatCalendarDate('2026-01-01', 'en-US')).toBe('Jan 1, 2026')
    expect(formatDateTime(null, 'en-US', 'Asia/Shanghai')).toBe('')
  })
  it.each([
    ['2026-03-08', '2026-03-09', 'America/New_York', 23],
    ['2026-11-01', '2026-11-02', 'America/New_York', 25],
    ['2026-03-08', '2026-03-09', 'Asia/Shanghai', 24],
  ])('uses the real local day length for %s in %s', (start, end, zone, hours) => {
    expect((Date.parse(startOfZonedDate(end, zone)) - Date.parse(startOfZonedDate(start, zone))) / 3600000).toBe(hours)
  })
  it('finds the start of a date with a midnight DST gap', () => {
    expect(startOfZonedDate('2026-09-06', 'America/Santiago')).toBe('2026-09-06T04:00:00.000Z')
  })
  it('applies the selected zone to list date filters without changing Relay pagination', () => {
    const result = usersQueryVariables(validateUsersSearch({
      createdFrom: '2026-03-08', createdTo: '2026-03-08', before: 'cursor-before',
    }), 'America/New_York')
    expect(result).toMatchObject({
      last: 10, before: 'cursor-before',
      filter: { createdFrom: '2026-03-08T05:00:00.000Z', createdBefore: '2026-03-09T04:00:00.000Z' },
    })
    expect(result?.first).toBeUndefined()
  })
})
