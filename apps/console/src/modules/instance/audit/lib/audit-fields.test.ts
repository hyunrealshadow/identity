import { describe, expect, it } from 'vitest'

import { appendLuceneClause, applyTimeRangePreset, buildAuditLuceneFields } from './audit-fields'

const descriptions = {
  action: 'Action',
  actorType: 'Actor type',
  actor: 'Actor ID',
  targetType: 'Target type',
  target: 'Target ID',
  resourceType: 'Resource type',
  resource: 'Resource ID',
  subject: 'Subject ID',
  operation: 'Operation',
  status: 'Status',
  previousStatus: 'Previous status',
  credentialType: 'Credential type',
  eventKind: 'Event kind',
  requestId: 'Request ID',
  traceId: 'Trace ID',
  reason: 'Reason',
  occurredAt: 'Occurred at',
}

describe('audit-fields', () => {
  it('merges live actions ahead of static suggestions without duplicates', async () => {
    const fields = buildAuditLuceneFields(descriptions, ['custom.audit.action', 'user.create'])
    const actionField = fields.find((f) => f.name === 'action')
    expect(actionField).toBeDefined()
    const options = await actionField!.search!('custom', {
      field: actionField!,
      value: 'custom',
      position: 10,
      signal: new AbortController().signal,
    })
    expect(options.map((o) => o.value)).toEqual(['custom.audit.action'])
  })

  it('appends clauses without duplicates and quotes values with special characters', () => {
    expect(appendLuceneClause('', 'action', 'user.create')).toBe('action:user.create')
    expect(appendLuceneClause('action:user.create', 'action', 'user.create')).toBe(
      'action:user.create',
    )
    expect(appendLuceneClause('action:user.create', 'reason', 'two words')).toBe(
      'action:user.create AND reason:"two words"',
    )
    expect(appendLuceneClause('action:user.create', 'requestId', 'req:123')).toBe(
      'action:user.create AND requestId:"req:123"',
    )
  })

  it('replaces existing occurredAt clauses when applying time presets', () => {
    expect(applyTimeRangePreset('', '[now-24h TO now]')).toBe('occurredAt:[now-24h TO now]')
    expect(applyTimeRangePreset('action:user.create', '[now-15m TO now]')).toBe(
      'occurredAt:[now-15m TO now] AND action:user.create',
    )
    expect(
      applyTimeRangePreset(
        'occurredAt:[now-24h TO now] AND action:user.create',
        '[now-7d TO now]',
      ),
    ).toBe('occurredAt:[now-7d TO now] AND action:user.create')
  })
})
