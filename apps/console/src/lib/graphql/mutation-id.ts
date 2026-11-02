/** Correlation only; this value does not make a mutation idempotent. */
export function nextClientMutationId(): string {
  try {
    const value = globalThis.crypto?.randomUUID?.()
    if (value) return value
  } catch {
    // A blocked crypto implementation still gets an opaque correlation value.
  }
  return `console-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
}
