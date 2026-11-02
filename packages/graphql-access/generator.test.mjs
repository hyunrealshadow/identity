import { describe, expect, it } from 'vitest'

import {
  parseSchemaMetadata,
} from './generator.mjs'

const SDL = `
  directive @access(policy: AccessPolicy!) repeatable on FIELD_DEFINITION

  input AccessPolicy {
    scopes: [String!]!
    authentication: AccessAuthentication!
    maxAge: Int
    elevatedMaxAge: Int
    userOnly: Boolean!
    runtime: Boolean!
  }

  enum AccessAuthentication {
    SESSION
    AAL2
    RECENT
    RECENT_AAL2
    ACCOUNT_SECURITY
  }

  interface Node {
    id: ID!
  }

  type User implements Node {
    id: ID!
    email: String!
  }

  type QueryRoot {
    viewer: User! @access(policy: { scopes: [], authentication: SESSION, maxAge: null, elevatedMaxAge: null, userOnly: true, runtime: false })
    nodes: [Node!]! @access(policy: { scopes: ["management.user.read"], authentication: RECENT, maxAge: 300, userOnly: true, runtime: true })
    admin: String! @access(policy: { scopes: ["admin.read"], authentication: RECENT, maxAge: 300, userOnly: true, runtime: false }) @access(policy: { scopes: ["admin.write"], authentication: AAL2, userOnly: true, runtime: true })
  }

  type MutationRoot {
    update: Boolean! @access(policy: { scopes: [], authentication: SESSION, userOnly: true, runtime: false })
  }

  schema {
    query: QueryRoot
    mutation: MutationRoot
  }
`

describe('graphql-access generator', () => {
  it('captures named return types, repeatable policies and root names', () => {
    const metadata = parseSchemaMetadata(SDL)

    expect(metadata.queryTypeName).toBe('QueryRoot')
    expect(metadata.mutationTypeName).toBe('MutationRoot')

    const nodes = metadata.types.QueryRoot.fields.nodes
    expect(nodes.returnType).toBe('Node')
    expect(nodes.policies).toEqual([
      {
        scopes: ['management.user.read'],
        authentication: 'RECENT',
        userOnly: true,
        runtime: true,
        maxAge: 300,
      },
    ])

    const admin = metadata.types.QueryRoot.fields.admin
    expect(admin.policies).toHaveLength(2)
    expect(admin.policies[0].scopes).toEqual(['admin.read'])
    expect(admin.policies[1].scopes).toEqual(['admin.write'])

    expect(metadata.types.Node.kind).toBe('INTERFACE')
    expect(metadata.types.Node.possibleTypes).toEqual(['User'])
    expect(metadata.types.User.interfaces).toEqual(['Node'])
    expect(metadata.types.User.fields.email.policies).toEqual([])
  })


  it('rejects a root field without access metadata', () => {
    const missing = SDL.replace(
      ' @access(policy: { scopes: [], authentication: SESSION, maxAge: null, elevatedMaxAge: null, userOnly: true, runtime: false })',
      '',
    )
    expect(() => parseSchemaMetadata(missing)).toThrow(/missing @access metadata/)
  })
})
