import { describe, expect, it } from 'vitest'

import zhCN from '../locales/zh-CN'
import { appendLuceneClause, applyTimeRangePreset, buildAuditLuceneFields } from './audit-fields'
import { AUDIT_ACTION_LABELS } from './audit-labels'

const t = (key: string) => (zhCN as Record<string, string>)[key] ?? key

function context(field: ReturnType<typeof buildAuditLuceneFields>[number], value: string) {
  return { field, value, position: value.length, signal: new AbortController().signal }
}

describe('audit-fields', () => {
  it('offers every action of the schema as its stored value with a localized name', async () => {
    const fields = buildAuditLuceneFields(t as never)
    const action = fields.find((field) => field.name === 'action')!
    const options = await action.search!('角色权限', context(action, '角色权限'))
    expect(options).toEqual([
      { label: 'role_permission_update', value: 'role_permission_update', detail: '修改了角色权限' },
    ])
    const all = await action.search!('', context(action, ''))
    expect(all).toHaveLength(Object.keys(AUDIT_ACTION_LABELS).length)
  })

  it('completes enumerated fields only; identifiers and labels stay free text', () => {
    const fields = buildAuditLuceneFields(t as never)
    const withValues = fields.filter((field) => field.search).map((field) => field.name)
    expect(withValues).toEqual([
      'category',
      'action',
      'outcome',
      'failureReason',
      'actorKind',
      'targetKind',
      'authMethod',
    ])
  })

  it('appends clauses without duplicates and quotes values with special characters', () => {
    expect(appendLuceneClause('', 'action', 'user_create')).toBe('action:user_create')
    expect(appendLuceneClause('action:user_create', 'action', 'user_create')).toBe(
      'action:user_create',
    )
    expect(appendLuceneClause('action:user_create', 'targetLabel', 'two words')).toBe(
      'action:user_create AND targetLabel:"two words"',
    )
    expect(appendLuceneClause('action:user_create', 'requestId', 'req:123')).toBe(
      'action:user_create AND requestId:"req:123"',
    )
  })

  it('replaces existing occurredAt clauses when applying time presets', () => {
    expect(applyTimeRangePreset('', '[now-24h TO now]')).toBe('occurredAt:[now-24h TO now]')
    expect(applyTimeRangePreset('action:user_create', '[now-15m TO now]')).toBe(
      'occurredAt:[now-15m TO now] AND action:user_create',
    )
    expect(
      applyTimeRangePreset(
        'occurredAt:[now-24h TO now] AND action:user_create',
        '[now-7d TO now]',
      ),
    ).toBe('occurredAt:[now-7d TO now] AND action:user_create')
    expect(
      applyTimeRangePreset(
        'occurredAt:(>=2026-11-01 AND <=2026-11-02) OR action:user_create',
        '[now-7d TO now]',
      ),
    ).toBe('occurredAt:[now-7d TO now] AND action:user_create')
    expect(
      applyTimeRangePreset(
        'action:user_create OR occurredAt:(now-1h)',
        '[now-7d TO now]',
      ),
    ).toBe('occurredAt:[now-7d TO now] AND action:user_create')
  })
})
