import { describe, expect, it } from 'vitest'

import { auditChangeValueText } from './audit-presentation'

describe('auditChangeValueText', () => {
  it('shows references by name and translations by locale', () => {
    expect(auditChangeValueText({ kind: 'role', oid: '4a3806f7-e6df', label: 'Auditors' }, '-')).toBe(
      'Auditors',
    )
    expect(auditChangeValueText({ kind: 'user', oid: '4a3806f7-e6df' }, '-')).toBe('4a3806f7')
    expect(auditChangeValueText([{ locale: 'zh-CN', value: '审计员' }], '-')).toBe('zh-CN: 审计员')
  })

  it('shows absent and empty values with the empty label', () => {
    expect(auditChangeValueText(null, '空')).toBe('空')
    expect(auditChangeValueText([], '空')).toBe('空')
    expect(auditChangeValueText(false, '空')).toBe('false')
  })
})
