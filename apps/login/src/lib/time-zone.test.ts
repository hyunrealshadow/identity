import { describe, expect, it, vi } from 'vitest'

import {
  BROWSER_TIME_ZONE_VALUE,
  UTC_TIME_ZONE,
  formatAccountDate,
  formatAccountExactDateTime,
  formatRecentActivity,
  initialTimeZoneValues,
  isValidTimeZone,
  resolveAccountTimeZone,
  timeZonePreferenceValue,
  timeZoneSelectionValue,
  timeZoneValues,
  zonedDateParts,
} from './time-zone'

const timeFormat = {
  hour: '2-digit',
  minute: '2-digit',
  hour12: false,
} satisfies Intl.DateTimeFormatOptions

describe('account time zone preference', () => {
  it('accepts IANA identifiers and rejects offsets or unknown zones', () => {
    expect(isValidTimeZone('Asia/Shanghai')).toBe(true)
    expect(isValidTimeZone('America/New_York')).toBe(true)
    expect(isValidTimeZone('Asia/Calcutta')).toBe(true)
    expect(isValidTimeZone('+02:00')).toBe(false)
    expect(isValidTimeZone('Not/AZone')).toBe(false)
    expect(isValidTimeZone(undefined)).toBe(false)
  })

  it('uses an explicit zone, then the browser, then UTC', () => {
    expect(resolveAccountTimeZone(undefined, 'America/New_York')).toBe('America/New_York')
    expect(resolveAccountTimeZone(null, 'America/New_York')).toBe('America/New_York')
    expect(resolveAccountTimeZone('Asia/Shanghai', 'America/New_York')).toBe('Asia/Shanghai')
    expect(resolveAccountTimeZone('Not/AZone', 'America/New_York')).toBe('America/New_York')
    expect(resolveAccountTimeZone(undefined, 'Not/AZone')).toBe(UTC_TIME_ZONE)
  })

  it('stores browser follow as an empty preference without inventing a zone', () => {
    expect(timeZonePreferenceValue(BROWSER_TIME_ZONE_VALUE)).toBeNull()
    expect(timeZonePreferenceValue('')).toBeNull()
    expect(timeZonePreferenceValue('Asia/Shanghai')).toBe('Asia/Shanghai')
    expect(timeZoneSelectionValue(undefined)).toBe(BROWSER_TIME_ZONE_VALUE)
    expect(timeZoneSelectionValue('Not/AZone')).toBe(BROWSER_TIME_ZONE_VALUE)
  })
})

describe('time zone options', () => {
  it('caches the runtime catalog without creating a formatter for every option', async () => {
    vi.resetModules()
    const module = await import('./time-zone')
    const supported = vi.spyOn(Intl as typeof Intl & { supportedValuesOf: (key: string) => string[] }, 'supportedValuesOf')
    const formatters = vi.spyOn(Intl, 'DateTimeFormat')
    try {
      const first = module.timeZoneValues('Asia/Calcutta')
      const second = module.timeZoneValues('America/New_York')
      expect(first).toContain('Asia/Calcutta')
      expect(second).toContain('America/New_York')
      expect(first).not.toContain('America/NotAZone')
      expect(supported).toHaveBeenCalledOnce()
      expect(formatters.mock.calls.length).toBeLessThanOrEqual(2)
    } finally {
      supported.mockRestore()
      formatters.mockRestore()
    }
  })

  it('keeps UTC, supported zones and a saved alias without duplicates', () => {
    const values = timeZoneValues('Asia/Calcutta')

    expect(values[0]).toBe(UTC_TIME_ZONE)
    expect(values).toContain('Asia/Calcutta')
    expect(values).toContain('Asia/Shanghai')
    expect(new Set(values).size).toBe(values.length)
  })

  it('serves a hydration-stable initial list', () => {
    expect(initialTimeZoneValues('Asia/Calcutta')).toEqual([
      UTC_TIME_ZONE,
      'Asia/Calcutta',
    ])
    expect(initialTimeZoneValues(undefined)).toEqual([UTC_TIME_ZONE])
  })
})

describe('time zone formatting', () => {
  it('uses the chosen zone for day boundaries', () => {
    const instant = new Date('2026-10-25T23:30:00Z')

    expect(zonedDateParts(instant, 'Asia/Shanghai')).toEqual({
      year: 2026,
      month: 10,
      day: 26,
    })
    expect(zonedDateParts(instant, UTC_TIME_ZONE)).toEqual({
      year: 2026,
      month: 10,
      day: 25,
    })
  })

  it('renders exact times across a DST transition', () => {
    expect(formatAccountDate(
      '2026-03-08T06:30:00Z',
      'en-GB',
      'America/New_York',
      timeFormat,
    )).toBe('01:30')
    expect(formatAccountDate(
      '2026-03-08T07:30:00Z',
      'en-GB',
      'America/New_York',
      timeFormat,
    )).toBe('03:30')
    expect(formatAccountExactDateTime(
      '2026-03-08T07:30:00Z',
      'en-US',
      'America/New_York',
    )).toContain('Mar 8, 2026')
  })

  it('falls back to UTC for an unsupported formatting zone', () => {
    expect(formatAccountDate(
      '2026-10-25T23:30:00Z',
      'en-GB',
      'Not/AZone',
      timeFormat,
    )).toBe(formatAccountDate(
      '2026-10-25T23:30:00Z',
      'en-GB',
      UTC_TIME_ZONE,
      timeFormat,
    ))
  })

  it('computes same-day, yesterday and weekday labels in the chosen zone', () => {
    const now = new Date('2026-10-26T00:30:00Z')
    const sameDay = new Date('2026-10-25T23:30:00Z')
    const yesterday = new Date('2026-10-24T23:30:00Z')
    const weekday = new Date('2026-10-23T04:00:00Z')

    expect(formatRecentActivity(sameDay, 'en-US', 'Asia/Shanghai', now))
      .toBe(new Intl.DateTimeFormat('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        timeZone: 'Asia/Shanghai',
      }).format(sameDay))
    expect(formatRecentActivity(yesterday, 'en-US', 'Asia/Shanghai', now))
      .toBe(new Intl.RelativeTimeFormat('en-US', { numeric: 'auto' }).format(-1, 'day'))
    expect(formatRecentActivity(weekday, 'en-US', 'Asia/Shanghai', now))
      .toBe(new Intl.DateTimeFormat('en-US', {
        weekday: 'short',
        timeZone: 'Asia/Shanghai',
      }).format(weekday))
  })

  it('uses the chosen zone when comparing the relative year', () => {
    const date = '2025-12-31T23:30:00Z'
    expect(formatRecentActivity(
      date,
      'en-US',
      'Asia/Shanghai',
      '2026-02-01T00:00:00Z',
    )).toBe(new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      timeZone: 'Asia/Shanghai',
    }).format(new Date(date)))
  })

  it('uses a medium date beyond the current zone year and rejects invalid dates', () => {
    const date = '2024-12-31T23:30:00Z'
    expect(formatRecentActivity(
      date,
      'en-US',
      'Asia/Shanghai',
      '2026-02-01T00:00:00Z',
    )).toBe(new Intl.DateTimeFormat('en-US', {
      dateStyle: 'medium',
      timeZone: 'Asia/Shanghai',
    }).format(new Date(date)))
    expect(formatRecentActivity('not-a-date', 'en-US', UTC_TIME_ZONE)).toBe('')
    expect(formatAccountDate('not-a-date', 'en-US', UTC_TIME_ZONE, timeFormat)).toBe('')
  })
})
