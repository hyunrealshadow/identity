const STORAGE_KEY = 'identity.console.audit.query-history'
const MAX_ENTRIES = 20

/** Recent audit queries in this browser, most recent first. */
export function readAuditQueryHistory(): string[] {
  try {
    const parsed: unknown = JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? '[]')
    return Array.isArray(parsed)
      ? parsed.filter((entry): entry is string => typeof entry === 'string' && entry.trim() !== '')
      : []
  } catch {
    return []
  }
}

/** Moves `query` to the front of `history`, without duplicates. */
export function withAuditQuery(history: readonly string[], query: string): string[] {
  const trimmed = query.trim()
  if (!trimmed) return [...history]
  return [trimmed, ...history.filter((entry) => entry !== trimmed)].slice(0, MAX_ENTRIES)
}

export function writeAuditQueryHistory(history: readonly string[]): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(history))
  } catch {
    // Storage can be unavailable (private mode, blocked site data); history is a convenience.
  }
}
