import { useSyncExternalStore } from 'react'

export const BROWSER_TIME_ZONE_VALUE = 'browser'
export const UTC_TIME_ZONE = 'UTC'

const FALLBACK_TIME_ZONES = [
  'Europe/London',
  'Europe/Paris',
  'Asia/Shanghai',
  'Asia/Tokyo',
  'America/New_York',
  'America/Los_Angeles',
  'Australia/Sydney',
] as const

/**
 * Browser detection is a display fallback, never a saved preference. An
 * explicit IANA zone always wins; an unsupported saved value follows the
 * browser, and an unusable browser value falls back to UTC.
 */
export function isValidTimeZone(value: string | null | undefined): value is string {
  if (typeof value !== 'string') return false
  const zone = value.trim()
  // Intl accepts UTC offsets in some runtimes, but the account contract stores
  // IANA identifiers only.
  if (!zone || zone.startsWith('+') || zone.startsWith('-')) return false
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: zone }).format(0)
    return true
  } catch {
    return false
  }
}

export function browserTimeZone() {
  try {
    const zone = new Intl.DateTimeFormat().resolvedOptions().timeZone
    return isValidTimeZone(zone) ? zone : UTC_TIME_ZONE
  } catch {
    return UTC_TIME_ZONE
  }
}

export function resolveAccountTimeZone(
  preference: string | null | undefined,
  browserZone: string | null | undefined = browserTimeZone(),
) {
  const explicit = typeof preference === 'string' ? preference.trim() : ''
  if (isValidTimeZone(explicit)) return explicit
  const browser = typeof browserZone === 'string' ? browserZone.trim() : ''
  return isValidTimeZone(browser) ? browser : UTC_TIME_ZONE
}

export function timeZonePreferenceValue(value: string | null | undefined) {
  const normalized = value?.trim()
  return !normalized || normalized === BROWSER_TIME_ZONE_VALUE ? null : normalized
}

export function timeZoneSelectionValue(preference: string | null | undefined) {
  const normalized = typeof preference === 'string' ? preference.trim() : ''
  return isValidTimeZone(normalized) ? normalized : BROWSER_TIME_ZONE_VALUE
}

/**
 * UTC and the current alias are enough for the first render. The full ICU list
 * is added after hydration so a difference between the server and browser ICU
 * data cannot change the collection during hydration.
 */
export function initialTimeZoneValues(selected?: string | null) {
  const values = [UTC_TIME_ZONE]
  const selectedZone = timeZoneSelectionValue(selected)
  if (selectedZone !== BROWSER_TIME_ZONE_VALUE && selectedZone !== UTC_TIME_ZONE) {
    values.push(selectedZone)
  }
  return values
}

export function timeZoneValues(selected?: string | null) {
  const values = initialTimeZoneValues(selected)
  const supported = supportedTimeZones()
  return [...new Set([...values, ...(supported.length ? supported : FALLBACK_TIME_ZONES)])]
}

export function safeTimeZone(value: string | null | undefined) {
  return isValidTimeZone(value) ? value.trim() : UTC_TIME_ZONE
}

export function formatAccountDate(
  value: string | number | Date,
  locale: string,
  timeZone: string,
  options: Intl.DateTimeFormatOptions,
) {
  const date = validDate(value)
  if (!date) return ''
  return new Intl.DateTimeFormat(locale, {
    ...options,
    timeZone: safeTimeZone(timeZone),
  }).format(date)
}

export function formatAccountExactDateTime(
  value: string | number | Date,
  locale: string,
  timeZone: string,
) {
  return formatAccountDate(value, locale, timeZone, {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}

export function formatRecentActivity(
  value: string | number | Date,
  locale: string,
  timeZone: string,
  now: string | number | Date = new Date(),
) {
  const date = validDate(value)
  const current = validDate(now) ?? new Date()
  if (!date) return ''
  const zone = safeTimeZone(timeZone)
  const dateDay = zonedDayNumber(date, zone)
  const currentDay = zonedDayNumber(current, zone)

  if (dateDay === currentDay) {
    return formatAccountDate(date, locale, zone, {
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  const dayDifference = currentDay - dateDay
  if (dayDifference === 1) {
    return new Intl.RelativeTimeFormat(locale, { numeric: 'auto' })
      .format(-1, 'day')
  }
  if (dayDifference > 1 && dayDifference < 7) {
    return formatAccountDate(date, locale, zone, { weekday: 'short' })
  }

  const sameYear = zonedDateParts(date, zone).year
    === zonedDateParts(current, zone).year
  if (sameYear) {
    return formatAccountDate(date, locale, zone, {
      month: 'short',
      day: 'numeric',
    })
  }
  return formatAccountDate(date, locale, zone, { dateStyle: 'medium' })
}

export function zonedDateParts(value: Date, timeZone: string) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: safeTimeZone(timeZone),
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).formatToParts(value)
  const numberPart = (type: string) =>
    Number(parts.find((part) => part.type === type)?.value ?? 0)
  return {
    year: numberPart('year'),
    month: numberPart('month'),
    day: numberPart('day'),
  }
}

function zonedDayNumber(value: Date, timeZone: string) {
  const { year, month, day } = zonedDateParts(value, timeZone)
  return Math.floor(Date.UTC(year, month - 1, day) / 86_400_000)
}

function validDate(value: string | number | Date) {
  const date = value instanceof Date ? value : new Date(value)
  return Number.isNaN(date.getTime()) ? undefined : date
}

let supportedTimeZoneCache: string[] | undefined

function supportedTimeZones() {
  if (supportedTimeZoneCache) return supportedTimeZoneCache
  try {
    const supportedValuesOf = (Intl as typeof Intl & {
      supportedValuesOf?: (key: string) => string[]
    }).supportedValuesOf
    if (typeof supportedValuesOf !== 'function') return []
    const values = supportedValuesOf('timeZone')
    // These identifiers come from the runtime's own supported catalog.
    supportedTimeZoneCache = Array.isArray(values)
      ? values.filter((zone) => typeof zone === 'string' && zone !== UTC_TIME_ZONE)
      : []
    return supportedTimeZoneCache
  } catch {
    return []
  }
}

function subscribeToBrowserTimeZone(notify: () => void) {
  window.addEventListener('focus', notify)
  document.addEventListener('visibilitychange', notify)
  return () => {
    window.removeEventListener('focus', notify)
    document.removeEventListener('visibilitychange', notify)
  }
}

/** Hydrates with UTC, then follows the browser unless an explicit zone is set. */
export function useAccountTimeZone(preference?: string | null) {
  const browserZone = useSyncExternalStore(
    subscribeToBrowserTimeZone,
    browserTimeZone,
    () => UTC_TIME_ZONE,
  )
  return resolveAccountTimeZone(preference, browserZone)
}
