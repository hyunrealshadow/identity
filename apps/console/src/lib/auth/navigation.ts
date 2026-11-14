/** Restart the Console from a fresh document load. */
export function reloadDocument(): void {
  window.location.reload()
}

/** Replace the Console document with another address. */
export function assignDocument(url: string): void {
  window.location.assign(url)
}
