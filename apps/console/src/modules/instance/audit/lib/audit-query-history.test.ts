import { beforeEach, describe, expect, it } from 'vitest'

import { readAuditQueryHistory, withAuditQuery, writeAuditQueryHistory } from './audit-query-history'

describe('audit query history', () => {
  beforeEach(() => window.localStorage.clear())

  it('keeps the latest query first without duplicates', () => {
    const history = withAuditQuery(withAuditQuery(['a', 'b'], 'b '), '  ')
    expect(history).toEqual(['b', 'a'])
  })

  it('round-trips through storage and ignores corrupt entries', () => {
    writeAuditQueryHistory(['outcome:failure'])
    expect(readAuditQueryHistory()).toEqual(['outcome:failure'])
    window.localStorage.setItem('identity.console.audit.query-history', '{"not":"a list"}')
    expect(readAuditQueryHistory()).toEqual([])
  })
})
