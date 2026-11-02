// @vitest-environment node
import { describe, expect, it } from 'vitest'

import {
  permissionDisplayDescription,
  permissionDisplayName,
  roleDisplayDescription,
  roleDisplayName,
  roleIsBuiltIn,
  withPermissionDisplayFields,
  withRoleDisplayFields,
} from '#/modules/user-management/roles/lib/role-localization'

describe('role localized display text', () => {
  it('prefers exact and parent translations, then independent default text', () => {
    const role = withRoleDisplayFields({
      name: 'Operations',
      description: 'Default operations role',
      builtIn: true,
      names: [
        { locale: 'en-US', value: 'Operations' },
        { locale: 'zh', value: '运营组' },
        { locale: 'zh-CN', value: '运营' },
        { locale: 'fr-FR', value: 'Opérations' },
      ],
      descriptions: [
        { locale: 'en-US', value: 'Day-to-day operations' },
        { locale: 'zh-CN', value: '日常运营' },
      ],
    })

    expect(roleDisplayName(role, 'en-US')).toBe('Operations')
    expect(roleDisplayName(role, 'zh-CN')).toBe('运营')
    expect(roleDisplayName(role, 'zh-Hans-CN')).toBe('运营组')
    expect(roleDisplayName(role, 'fr-FR')).toBe('Opérations')
    expect(roleDisplayName(role, 'de-DE')).toBe('Operations')
    expect(roleDisplayDescription(role, 'en-US')).toBe('Day-to-day operations')
    expect(roleDisplayDescription(role, 'de-DE')).toBe('Default operations role')
    expect(roleIsBuiltIn(role)).toBe(true)
  })

  it('falls back to canonical role text and permission code without inventing entries', () => {
    const role = withRoleDisplayFields({
      name: 'Auditors',
      description: 'Read-only review',
      names: [],
      descriptions: [],
    })
    expect(roleDisplayName(role, 'zh-CN')).toBe('Auditors')
    expect(roleDisplayDescription(role, 'zh-CN')).toBe('Read-only review')

    const permission = withPermissionDisplayFields({
      code: 'management.user.read',
      name: 'Read users',
      description: null,
      builtIn: true,
      names: [
        { locale: 'en-US', value: 'Read users' },
        { locale: 'zh-CN', value: '读取用户' },
      ],
      descriptions: [],
    })
    expect(permissionDisplayName(permission, 'zh-CN')).toBe('读取用户')
    expect(permissionDisplayName(permission, 'en-US')).toBe('Read users')
    expect(permissionDisplayDescription(permission, 'en-US')).toBeUndefined()

    const untranslated = withPermissionDisplayFields({
      code: 'management.user.read',
      name: null,
      description: null,
      names: [],
      descriptions: [],
    })
    expect(permissionDisplayName(untranslated, 'en-US')).toBe(
      'management.user.read',
    )
  })
})
