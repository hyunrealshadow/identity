import { describe, expect, it } from 'vitest'

import type { AuditEventFieldsFragment } from '#/generated/graphql'
import enUS from '../locales/en-US'
import zhCN from '../locales/zh-CN'
import { auditChangeValueText, auditSentence } from './audit-presentation'

function translator(messages: Record<string, string>) {
  return (key: string, values: Record<string, string | number> = {}) =>
    (messages[key] ?? key).replace(/\{(\w+)\}/g, (_, name: string) => String(values[name] ?? ''))
}

function event(overrides: Partial<AuditEventFieldsFragment>): AuditEventFieldsFragment {
  return {
    id: 'e1',
    occurredAt: '2026-11-21T02:19:00Z',
    category: 'AUTHORIZATION',
    action: 'TOKEN_REPLAY',
    outcome: 'FAILURE',
    failureReason: 'REPLAY_DETECTED',
    actor: { kind: 'CLIENT', id: null, oid: 'c1', label: 'Console', user: null, client: null },
    target: { kind: 'USER', id: null, oid: 'u1', label: 'verifyadmin' },
    clientId: null,
    authMethods: [],
    ipAddress: null,
    userAgent: null,
    requestId: null,
    traceId: null,
    changes: [],
    ...overrides,
  }
}

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

describe('auditSentence', () => {
  it('places the actor and target where each language puts them', () => {
    const replay = event({})
    expect(auditSentence(replay, 'zh-CN', translator(zhCN) as never)).toEqual([
      { text: 'Console', role: 'actor' },
      { text: ' 重复使用了 ' },
      { text: 'verifyadmin', role: 'target' },
      { text: ' 已失效的令牌' },
    ])
    const signIn = event({ category: 'SIGN_IN', action: 'SIGN_IN', actor: { ...replay.actor, kind: 'ANONYMOUS', oid: null, label: null } })
    expect(
      auditSentence(signIn, 'en-US', translator(enUS) as never)
        .map((part) => part.text)
        .join(''),
    ).toBe('Sign-in to verifyadmin')
  })

  it('says the account does not exist when a sign-in has no target', () => {
    const unknown = event({
      category: 'SIGN_IN',
      action: 'SIGN_IN',
      outcome: 'FAILURE',
      failureReason: 'UNKNOWN_ACCOUNT',
      target: null,
    })
    expect(
      auditSentence(unknown, 'zh-CN', translator(zhCN) as never)
        .map((part) => part.text)
        .join(''),
    ).toBe('尝试登录不存在的账户')
  })
})
