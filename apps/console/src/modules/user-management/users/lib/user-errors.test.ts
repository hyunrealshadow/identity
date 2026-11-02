// @vitest-environment node
import { describe, expect, it } from 'vitest'

import { versionConflict } from '#/modules/user-management/users/lib/user-errors'
import type { GraphQLIssue } from '#/lib/graphql/transport'

const CURRENT_VERSION = '9f0c2b1a-3d4e-4f50-8a9b-1c2d3e4f5a6b'

function issue(overrides: Partial<GraphQLIssue> = {}): GraphQLIssue {
  return {
    message: 'The user changed while you were working.',
    fields: [],
    ...overrides,
  }
}

describe('versionConflict', () => {
  it('tolerates a forward-compatible nested params version', () => {
    const result = versionConflict([
      issue({
        kind: 'conflict',
        code: 16008,
        fields: [
          {
            path: 'expectedVersion',
            code: 16008,
            message: 'The user changed while you were working.',
          },
        ],
        extensions: {
          kind: 'conflict',
          code: 16008,
          fields: [{ field: 'expectedVersion', code: 16008 }],
          params: { current_version: CURRENT_VERSION },
        },
      }),
    ])

    expect(result).toEqual({ conflict: true, currentVersion: CURRENT_VERSION })
  })

  it('recognizes the current backend shape without params', () => {
    const result = versionConflict([
      issue({
        kind: 'conflict',
        code: 16008,
        fields: [
          {
            path: 'expectedVersion',
            code: 16008,
            message: 'The user changed while you were working.',
          },
        ],
        extensions: {
          kind: 'conflict',
          code: 16008,
          fields: [
            {
              field: 'expectedVersion',
              code: 16008,
              message: 'The user changed while you were working.',
            },
          ],
          requestId: 'req-0123456789',
          traceId: '0af7651916cd43dd8448eb211c80319c',
        },
      }),
    ])

    expect(result).toStrictEqual({
      conflict: true,
      currentVersion: undefined,
    })
  })

  it('accepts the decimal string code and camelCase nested version', () => {
    const result = versionConflict([
      issue({
        kind: 'conflict',
        code: '16008',
        extensions: { params: { currentVersion: CURRENT_VERSION } },
      }),
    ])

    expect(result).toEqual({ conflict: true, currentVersion: CURRENT_VERSION })
  })

  it('does not treat identifier uniqueness conflicts as version conflicts', () => {
    const result = versionConflict([
      issue({
        kind: 'conflict',
        code: 15005,
        fields: [{ path: 'username', code: 15005 }],
        extensions: {
          kind: 'conflict',
          code: 16005,
          params: { current_version: CURRENT_VERSION },
        },
      }),
      issue({
        kind: 'conflict',
        code: 15006,
        fields: [{ path: 'email', code: 15006 }],
      }),
    ])

    expect(result).toEqual({ conflict: false })
  })

  it('does not infer a conflict from a non-code version hint', () => {
    const result = versionConflict([
      issue({
        kind: 'conflict',
        code: 16009,
        extensions: { current_version: CURRENT_VERSION },
      }),
    ])

    expect(result).toEqual({ conflict: false })
  })

  it('handles missing and malformed extensions safely', () => {
    const missing = versionConflict([issue({ code: 16008 })])
    expect(missing.conflict).toBe(true)
    expect(missing.currentVersion).toBeUndefined()

    const malformed = versionConflict([
      issue({
        code: 16008,
        extensions: {
          params: ['current_version'],
          current_version: { value: CURRENT_VERSION },
        },
      }),
    ])
    expect(malformed.conflict).toBe(true)
    expect(malformed.currentVersion).toBeUndefined()
  })
})
