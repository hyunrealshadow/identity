import type { Locale } from '#/lib/i18n'
import { resolveTimeZone } from '#/lib/time-zone'

function parsed(value: string | null | undefined): Date | null {
  if (!value) return null
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

export function formatDateTime(value: string | null | undefined, locale: Locale, timeZone?: string): string {
  const date = parsed(value)
  if (!date) return ''
  return new Intl.DateTimeFormat(locale, {
    timeZone: resolveTimeZone(timeZone),
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
}

export function formatDate(value: string | null | undefined, locale: Locale): string {
  const date = parsed(value)
  if (!date) return ''
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeZone: 'UTC' }).format(date)
}

export function formatNumber(value: number, locale: Locale): string {
  return new Intl.NumberFormat(locale).format(value)
}

/** Format a calendar-day label without shifting it into a different date. */
export function formatCalendarDay(value: string | null | undefined, locale: Locale): string {
  const date = parsed(value)
  if (!date) return ''
  return new Intl.DateTimeFormat(locale, {
    timeZone: 'UTC',
    month: 'short',
    day: 'numeric',
  }).format(date)
}

/** A date-only value already grouped in the requested user time zone. */
export function formatCalendarDate(value: string | null | undefined, locale: Locale): string {
  const date = parsed(value)
  if (!date) return ''
  return new Intl.DateTimeFormat(locale, {
    timeZone: 'UTC',
    dateStyle: 'medium',
  }).format(date)
}

export function exactUtc(value: string | null | undefined): string | undefined {
  const date = parsed(value)
  return date?.toISOString()
}

/** Date and time to the second with the time zone, for records such as audit events. */
export function formatPreciseDateTime(
  value: string | null | undefined,
  locale: Locale,
  timeZone?: string,
): string {
  const date = parsed(value)
  if (!date) return ''
  const zone = resolveTimeZone(timeZone)
  const day = new Intl.DateTimeFormat(locale, { timeZone: zone, dateStyle: 'medium' }).format(date)
  const time = new Intl.DateTimeFormat(locale, { timeZone: zone, timeStyle: 'medium' }).format(date)
  const offset = new Intl.DateTimeFormat(locale, { timeZone: zone, timeZoneName: 'shortOffset' })
    .formatToParts(date)
    .find((part) => part.type === 'timeZoneName')?.value
  return offset ? `${day} ${time} (${offset})` : `${day} ${time}`
}
