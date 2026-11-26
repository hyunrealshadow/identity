// @vitest-environment node
import { describe, expect, it } from 'vitest'

import { cursorPage } from './cursor-page'

describe('connection page direction', () => {
  it('does not send a stale forward cursor with a backward request', () => {
    expect(cursorPage(10, 'stale-after', 'current-before')).toEqual({
      last: 10,
      before: 'current-before',
    })
  })
})
