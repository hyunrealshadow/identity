import { describe, expect, it } from 'vitest'
import {
  matchesTimeZone,
  timeZoneOption,
  timeZoneOptions,
} from './time-zone-options'

describe('time zone option presentation', () => {
  it('localizes names and preserves IANA identifiers as values', () => {
    const date = new Date('2026-10-29T00:00:00Z')
    const chinese = timeZoneOption('Asia/Shanghai', 'zh-CN', date)
    const english = timeZoneOption('Asia/Shanghai', 'en-US', date)
    expect(chinese.id).toBe('Asia/Shanghai')
    expect(chinese.name).toContain('中国')
    expect(chinese.offset).toBe('UTC+08:00')
    expect(english.name).toContain('China')
  })

  it('uses the date for daylight saving changes, including within one UTC hour', () => {
    expect(
      timeZoneOption(
        'America/New_York',
        'en-US',
        new Date('2026-01-01T00:00:00Z'),
      ).offset,
    ).toBe('UTC-05:00')
    expect(
      timeZoneOption(
        'America/New_York',
        'en-US',
        new Date('2026-07-01T00:00:00Z'),
      ).offset,
    ).toBe('UTC-04:00')
    expect(
      timeZoneOption(
        'Australia/Lord_Howe',
        'en-US',
        new Date('2026-10-03T15:29:00Z'),
      ).offset,
    ).toBe('UTC+10:30')
    expect(
      timeZoneOption(
        'Australia/Lord_Howe',
        'en-US',
        new Date('2026-10-03T15:31:00Z'),
      ).offset,
    ).toBe('UTC+11:00')
  })

  it('handles quarter-hour offsets and local calendar-day rollover', () => {
    const date = new Date('2026-10-29T23:30:00Z')
    expect(timeZoneOption('Asia/Kathmandu', 'en-US', date).offset).toBe(
      'UTC+05:45',
    )
    expect(timeZoneOption('Pacific/Kiritimati', 'en-US', date).offset).toBe(
      'UTC+14:00',
    )
    expect(timeZoneOption('UTC', 'en-US', date).offset).toBe('UTC+00:00')
  })

  it('sorts by current offset and retains saved aliases', () => {
    const options = timeZoneOptions(
      ['Asia/Calcutta', 'UTC', 'America/New_York'],
      'en-US',
      new Date('2026-10-29T00:00:00Z'),
    )
    expect(options.map((option) => option.id)).toEqual([
      'America/New_York',
      'UTC',
      'Asia/Calcutta',
    ])
  })

  it('searches localized names, city names, IANA identifiers and offset forms', () => {
    const date = new Date('2026-10-29T00:00:00Z')
    const shanghai = timeZoneOption('Asia/Shanghai', 'zh-CN', date)
    const newYork = timeZoneOption('America/New_York', 'en-US', date)
    for (const query of [
      '中国',
      'shanghai',
      'Asia/Shanghai',
      'UTC+08:00',
      'GMT+8',
    ]) {
      expect(matchesTimeZone(shanghai.searchText, query)).toBe(true)
    }
    expect(matchesTimeZone(newYork.searchText, 'new york')).toBe(true)
    expect(matchesTimeZone(shanghai.searchText, 'Not a timezone')).toBe(false)
  })
})
