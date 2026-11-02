/** A selector covers descendants at a dot boundary, never the bare parent. */
export function scopeMatches(selector: string, scope: string): boolean {
  if (selector === scope) return true
  if (!selector.endsWith('.*')) return false
  const prefix = selector.slice(0, -1)
  return scope.startsWith(prefix) && scope.length > prefix.length
}

export function validScopeSelector(scope: string): boolean {
  if (!scope.includes('*')) return /^[A-Za-z0-9._:-]+$/.test(scope)
  return /^[A-Za-z0-9_:-]+(?:\.[A-Za-z0-9_:-]+)*\.\*$/.test(scope)
}
