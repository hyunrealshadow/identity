type CursorPage =
  | { first: number; after?: string; last?: never; before?: never }
  | { last: number; before: string; first?: never; after?: never }

/** Keep the page size paired with the cursor's direction. */
export function cursorPage(
  size: number,
  after?: string,
  before?: string,
): CursorPage {
  if (before) return { last: size, before }
  return after ? { first: size, after } : { first: size }
}
