/** Saved IANA identifier, or the browser's current zone when unset/unsupported. */
export function resolveTimeZone(
  preference?: string | null,
  browserZone = Intl.DateTimeFormat().resolvedOptions().timeZone,
): string {
  for (const candidate of [preference, browserZone, 'UTC']) {
    if (!candidate) continue
    const zone = candidate.trim()
    if (!zone || /^[+-]/.test(zone)) continue
    try {
      return new Intl.DateTimeFormat('en-US', { timeZone: zone }).resolvedOptions().timeZone
    } catch {
      // Unsupported saved values follow the browser rather than breaking rendering.
    }
  }
  return 'UTC'
}

/** First instant of a calendar date in the chosen zone, including DST gaps. */
export function startOfZonedDate(value: string, timeZone: string): string {
  const center = Date.parse(`${value}T00:00:00Z`)
  if (!Number.isFinite(center) || new Date(center).toISOString().slice(0, 10) !== value) {
    throw new RangeError('Invalid calendar date')
  }
  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone: resolveTimeZone(timeZone), calendar: 'gregory', numberingSystem: 'latn',
    year: 'numeric', month: '2-digit', day: '2-digit',
  })
  const dateAt = (instant: number) => {
    const parts = formatter.formatToParts(instant)
    const part = (type: Intl.DateTimeFormatPartTypes) => parts.find((entry) => entry.type === type)!.value
    return `${part('year')}-${part('month')}-${part('day')}`
  }
  // Search the local date boundary rather than assuming a constant UTC offset
  // or a 24-hour day. A skipped date resolves to the next existing boundary.
  let lower = center - 36 * 60 * 60 * 1000
  let upper = center + 36 * 60 * 60 * 1000
  while (lower < upper) {
    const middle = Math.floor((lower + upper) / 2)
    if (dateAt(middle) < value) lower = middle + 1
    else upper = middle
  }
  return new Date(lower).toISOString()
}
