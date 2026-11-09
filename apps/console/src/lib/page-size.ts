/** Page sizes offered by collection tables; the API accepts at most 100 per page. */
export const PAGE_SIZE_OPTIONS = [10, 20, 50, 100] as const

/** Accept only an offered page size from search params or user input. */
export function parsePageSize(value: unknown): number | undefined {
  const size =
    typeof value === 'number'
      ? value
      : typeof value === 'string'
        ? Number(value)
        : Number.NaN
  return (PAGE_SIZE_OPTIONS as readonly number[]).includes(size)
    ? size
    : undefined
}
