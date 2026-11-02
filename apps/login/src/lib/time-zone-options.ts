import type { Locale } from './i18n'

export interface TimeZoneOption {
  id: string
  name: string
  offset: string
  offsetMinutes: number
  searchText: string
}

let catalogMinute = ''
const metadataCache = new Map<string, TimeZoneOption>()

export function timeZoneOption(
  zone: string,
  locale: Locale,
  date: Date,
): TimeZoneOption {
  const minute = String(Math.floor(date.getTime() / 60_000))
  if (catalogMinute !== minute) {
    metadataCache.clear()
    catalogMinute = minute
  }
  const key = `${locale}:${zone}`
  const cached = metadataCache.get(key)
  if (cached) return cached
  const parts = new Intl.DateTimeFormat(`${locale}-u-ca-gregory-nu-latn`, {
    timeZone: zone,
    timeZoneName: 'long',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(date)
  const part = (type: Intl.DateTimeFormatPartTypes) =>
    parts.find((item) => item.type === type)?.value ?? ''
  const local = Date.UTC(
    Number(part('year')),
    Number(part('month')) - 1,
    Number(part('day')),
    Number(part('hour')),
    Number(part('minute')),
  )
  const offsetMinutes =
    (local - Math.floor(date.getTime() / 60_000) * 60_000) / 60_000
  const sign = offsetMinutes < 0 ? '-' : '+'
  const hours = Math.floor(Math.abs(offsetMinutes) / 60)
  const minutes = Math.abs(offsetMinutes) % 60
  const offset = `UTC${sign}${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}`
  const name = part('timeZoneName') || zone
  const compactOffset = `${sign}${hours}${minutes ? `:${String(minutes).padStart(2, '0')}` : ''}`
  const option = {
    id: zone,
    name,
    offset,
    offsetMinutes,
    searchText: `${zone} ${zone.replaceAll('_', ' ')} ${name} ${offset} GMT${compactOffset} UTC${compactOffset}`,
  }
  metadataCache.set(key, option)
  return option
}

export function timeZoneOptions(
  zones: readonly string[],
  locale: Locale,
  date: Date,
) {
  return zones
    .map((zone) => timeZoneOption(zone, locale, date))
    .sort(
      (a, b) => a.offsetMinutes - b.offsetMinutes || a.id.localeCompare(b.id),
    )
}

export function matchesTimeZone(text: string, query: string) {
  const normalized = text
    .toLocaleLowerCase()
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
  return query
    .toLocaleLowerCase()
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
    .trim()
    .split(/\s+/)
    .every((term) => normalized.includes(term))
}
