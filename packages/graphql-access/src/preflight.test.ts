import { describe, expect, it } from 'vitest'

import { createPreflight } from './preflight'
import type {
  AccessPolicy,
  PreflightContext,
  SchemaField,
  SchemaMetadata,
  SchemaType,
} from './types'

function policy(overrides: Partial<AccessPolicy> = {}): AccessPolicy {
  return {
    scopes: [],
    authentication: 'SESSION',
    userOnly: false,
    runtime: false,
    ...overrides,
  }
}

function field(
  name: string,
  returnType: string,
  policies: readonly AccessPolicy[] = [],
): SchemaField {
  return { name, returnType, policies }
}

function objectType(
  fields: Record<string, SchemaField>,
  options: { interfaces?: readonly string[]; possibleTypes?: readonly string[] } = {},
): SchemaType {
  return {
    kind: 'OBJECT',
    interfaces: options.interfaces ?? [],
    possibleTypes: options.possibleTypes ?? [],
    fields,
  }
}

const schema: SchemaMetadata = {
  queryTypeName: 'QueryRoot',
  mutationTypeName: 'MutationRoot',
  types: {
    QueryRoot: objectType({
      viewer: field('viewer', 'User', [policy({ userOnly: true })]),
      admin: field('admin', 'String', [
        policy({
          scopes: ['admin.read'],
          authentication: 'RECENT',
          maxAge: 300,
        }),
      ]),
      aal2: field('aal2', 'String', [policy({ authentication: 'AAL2' })]),
      recent: field('recent', 'String', [
        policy({ authentication: 'RECENT', maxAge: 300 }),
      ]),
      security: field('security', 'String', [
        policy({
          authentication: 'ACCOUNT_SECURITY',
          maxAge: 300,
          elevatedMaxAge: 3_600,
        }),
      ]),
      dynamic: field('dynamic', 'String', [policy({ runtime: true })]),
      node: field('node', 'Node', [policy({ runtime: true })]),
      nodes: field('nodes', 'User', [policy({ userOnly: true })]),
      unknownReturn: field('unknownReturn', 'MissingType'),
    }),
    MutationRoot: objectType({
      write: field('write', 'Boolean', [
        policy({ scopes: ['admin.write'], userOnly: true }),
      ]),
      delete: field('delete', 'Boolean', [
        policy({ scopes: ['admin.delete'], runtime: true }),
      ]),
    }),
    User: objectType(
      {
        id: field('id', 'ID'),
        email: field('email', 'String', [policy({ scopes: ['profile.email'] })]),
        admin: field('admin', 'String', [policy({ scopes: ['admin.read'] })]),
        settings: field('settings', 'Settings'),
        groups: field('groups', 'String', [policy({ scopes: ['group.read'] })]),
      },
      { interfaces: ['Node'] },
    ),
    Settings: objectType({
      theme: field('theme', 'String'),
      secret: field('secret', 'String', [policy({ scopes: ['settings.secret'] })]),
    }),
    Group: objectType(
      {
        id: field('id', 'ID'),
        name: field('name', 'String', [policy({ scopes: ['group.read'] })]),
      },
      { interfaces: ['Node'] },
    ),
    Node: {
      kind: 'INTERFACE',
      interfaces: [],
      possibleTypes: ['Group', 'User'],
      fields: {
        id: field('id', 'ID'),
      },
    },
  },
}

const preflight = createPreflight(schema)
const NOW = 10_000

function context(overrides: Partial<PreflightContext> = {}): PreflightContext {
  return { scopes: [], user: true, acr: 'aal1', now: NOW, ...overrides }
}

function run(
  document: string,
  variables: Record<string, unknown> | undefined = {},
  overrides: Partial<PreflightContext> = {},
  operationName?: string,
) {
  return preflight(document, variables, context(overrides), operationName)
}

describe('preflightOperation scope handling', () => {
  it('inherits a parent policy for unannotated nested fields', () => {
    expect(
      run('query Q { viewer { settings { theme } } }'),
    ).toEqual({ status: 'allowed', requiredScopes: [] })
  })

  it('enforces an annotated nested field and keeps exact scope names', () => {
    expect(
      run('query Q { viewer { settings { secret } } }'),
    ).toEqual({ status: 'forbidden', requiredScopes: ['settings.secret'] })

    expect(
      run('query Q { viewer { settings { secret } } }', {}, {
        scopes: ['settings.secret.extra'],
      }),
    ).toEqual({ status: 'forbidden', requiredScopes: ['settings.secret'] })

    expect(
      run('query Q { viewer { settings { secret } } }', {}, {
        scopes: ['settings.secret'],
      }),
    ).toEqual({ status: 'allowed', requiredScopes: ['settings.secret'] })
  })

  it('resolves aliases and fragments against their actual field metadata', () => {
    const document = `
      query Q {
        ...RootAccess
      }
      fragment RootAccess on QueryRoot {
        aliased: admin
      }
    `

    expect(run(document, {}, { authTime: NOW })).toEqual({
      status: 'forbidden',
      requiredScopes: ['admin.read'],
    })
    expect(
      run(document, {}, { authTime: NOW, scopes: ['admin.read'] }),
    ).toEqual({ status: 'allowed', requiredScopes: ['admin.read'] })
  })

  it('applies inline fragments and ignores non-applicable abstract fragments', () => {
    expect(
      run('query Q { viewer { ... on User { email } } }'),
    ).toEqual({ status: 'forbidden', requiredScopes: ['profile.email'] })

    expect(
      run('query Q { viewer { id ... on Group { name } } }'),
    ).toEqual({ status: 'allowed', requiredScopes: [] })
  })

  it('evaluates @include and @skip with provided values and defaults', () => {
    const conditional = 'query Q($include: Boolean! = false) { admin @include(if: $include) }'
    expect(run(conditional)).toEqual({ status: 'allowed', requiredScopes: [] })
    expect(run(conditional, { include: true })).toEqual({
      status: 'forbidden',
      requiredScopes: ['admin.read'],
    })

    const skipped = 'query Q($skip: Boolean! = true) { admin @skip(if: $skip) }'
    expect(run(skipped)).toEqual({ status: 'allowed', requiredScopes: [] })
    expect(run(skipped, { skip: false }, { scopes: ['admin.read'], authTime: NOW })).toEqual({
      status: 'allowed',
      requiredScopes: ['admin.read'],
    })
  })

  it('marks an undecidable directive variable as unknown', () => {
    expect(
      run('query Q($include: Boolean!) { admin @include(if: $include) }'),
    ).toEqual({ status: 'unknown', requiredScopes: [] })
  })

  it('does not cache a decision from the same document with different variables', () => {
    const document = 'query Q($include: Boolean!) { admin @include(if: $include) }'
    expect(run(document, { include: false })).toEqual({
      status: 'allowed',
      requiredScopes: [],
    })
    expect(run(document, { include: true })).toEqual({
      status: 'forbidden',
      requiredScopes: ['admin.read'],
    })
  })
})

describe('preflightOperation authentication handling', () => {
  it('treats the max-age boundary as fresh and older or future times as stale', () => {
    const document = 'query Q { recent }'
    expect(run(document, {}, { authTime: NOW - 300 })).toEqual({
      status: 'allowed',
      requiredScopes: [],
    })
    expect(run(document, {}, { authTime: NOW - 301 })).toEqual({
      status: 'reauthentication',
      requiredScopes: [],
      maxAge: 300,
    })
    expect(run(document, {}, { authTime: NOW + 1 })).toEqual({
      status: 'reauthentication',
      requiredScopes: [],
      maxAge: 300,
    })
    expect(run(document)).toEqual({
      status: 'reauthentication',
      requiredScopes: [],
      maxAge: 300,
    })
  })

  it('requires AAL2 independently from freshness', () => {
    const document = 'query Q { aal2 }'
    expect(run(document, {}, { acr: 'aal1' })).toEqual({
      status: 'reauthentication',
      requiredScopes: [],
      acrValues: 'aal2',
    })
    expect(run(document, {}, { acr: 'aal2' })).toEqual({
      status: 'allowed',
      requiredScopes: [],
    })
    expect(run(document, {}, { acr: 'urn:example:aal2' })).toEqual({
      status: 'reauthentication',
      requiredScopes: [],
      acrValues: 'aal2',
    })
  })

  it('resolves ACCOUNT_SECURITY for known and unknown MFA state', () => {
    const document = 'query Q { security }'

    expect(
      run(document, {}, { mfaEnabled: true, acr: 'aal2', authTime: NOW - 299 }),
    ).toEqual({ status: 'allowed', requiredScopes: [] })
    expect(
      run(document, {}, { mfaEnabled: true, acr: 'aal2', authTime: NOW - 3_600 }),
    ).toEqual({ status: 'allowed', requiredScopes: [] })
    expect(
      run(document, {}, { mfaEnabled: true, acr: 'aal2', authTime: NOW - 3_601 }),
    ).toEqual({
      status: 'reauthentication',
      requiredScopes: [],
      acrValues: 'aal2',
      maxAge: 3_600,
    })
    expect(
      run(document, {}, { mfaEnabled: true, acr: 'aal1', authTime: NOW }),
    ).toEqual({
      status: 'reauthentication',
      requiredScopes: [],
      acrValues: 'aal2',
      maxAge: 3_600,
    })

    expect(
      run(document, {}, { mfaEnabled: false, acr: 'aal1', authTime: NOW - 300 }),
    ).toEqual({ status: 'allowed', requiredScopes: [] })
    expect(
      run(document, {}, { mfaEnabled: false, acr: 'aal1', authTime: NOW - 301 }),
    ).toEqual({
      status: 'reauthentication',
      requiredScopes: [],
      maxAge: 300,
    })

    expect(
      run(document, {}, { acr: 'aal2', authTime: NOW - 3_600 }),
    ).toEqual({ status: 'unknown', requiredScopes: [] })
    expect(run(document, {}, { acr: 'aal2', authTime: NOW - 3_601 })).toEqual({
      status: 'unknown',
      requiredScopes: [],
    })
    expect(run(document, {}, { acr: 'aal1', authTime: NOW })).toEqual({
      status: 'unknown',
      requiredScopes: [],
    })
  })

  it('lets a definite permission denial win over a fresh-auth prompt', () => {
    expect(
      run('query Q { admin aal2 }', {}, { acr: 'aal1' }),
    ).toEqual({ status: 'forbidden', requiredScopes: ['admin.read'] })
  })

  it('combines multiple field requirements conservatively', () => {
    expect(
      run('query Q { aal2 security recent }', {}, {
        mfaEnabled: true,
        acr: 'aal2',
        authTime: NOW - 301,
      }),
    ).toEqual({
      status: 'reauthentication',
      requiredScopes: [],
      acrValues: 'aal2',
      maxAge: 300,
    })
  })
})

describe('preflightOperation operation and document handling', () => {
  it('requires an operation name when the document contains multiple operations', () => {
    const document = 'query A { admin } query B { recent }'
    expect(run(document, {}, { scopes: ['admin.read'], authTime: NOW })).toEqual({
      status: 'unknown',
      requiredScopes: [],
    })
    expect(
      run(document, {}, { scopes: ['admin.read'], authTime: NOW }, 'A'),
    ).toEqual({ status: 'allowed', requiredScopes: ['admin.read'] })
    expect(run(document, {}, { authTime: NOW }, 'B')).toEqual({
      status: 'allowed',
      requiredScopes: [],
    })
    expect(run(document, {}, { authTime: NOW }, 'C')).toEqual({
      status: 'unknown',
      requiredScopes: [],
    })
  })

  it('marks parse errors and unknown fields as unknown', () => {
    expect(run('{')).toEqual({ status: 'unknown', requiredScopes: [] })
    expect(run('query Q { missing }')).toEqual({
      status: 'unknown',
      requiredScopes: [],
    })
  })

  it('marks a fragment cycle as unknown', () => {
    expect(
      run('query Q { ...A } fragment A on QueryRoot { ...A }'),
    ).toEqual({ status: 'unknown', requiredScopes: [] })
  })

  it('does not guess dynamic policy but still enforces static scopes', () => {
    expect(run('query Q { dynamic }')).toEqual({
      status: 'allowed',
      requiredScopes: [],
    })
    expect(run('mutation M { delete }')).toEqual({
      status: 'forbidden',
      requiredScopes: ['admin.delete'],
    })
    expect(run('mutation M { delete }', {}, { scopes: ['admin.delete'] })).toEqual({
      status: 'allowed',
      requiredScopes: ['admin.delete'],
    })
  })

  it('treats polymorphic Node targets as runtime policy with no universal scopes', () => {
    expect(run('query Q { node { id } }')).toEqual({
      status: 'allowed',
      requiredScopes: [],
    })
  })

  it('defers branch-specific abstract requirements instead of false denials', () => {
    const document = `
      query Q {
        node {
          id
          ... on User { email }
          ... on Group { name }
        }
      }
    `

    expect(run(document)).toEqual({
      status: 'forbidden',
      requiredScopes: ['group.read', 'profile.email'],
    })
    expect(run(document, {}, { scopes: ['profile.email'] })).toEqual({
      status: 'unknown',
      requiredScopes: ['group.read', 'profile.email'],
    })
    expect(run(document, {}, { scopes: ['profile.email', 'group.read'] })).toEqual({
      status: 'allowed',
      requiredScopes: ['group.read', 'profile.email'],
    })
  })

  it('requires a user principal when userOnly is set', () => {
    const document = 'query Q { viewer { id } }'
    expect(run(document, {}, { user: false })).toEqual({
      status: 'forbidden',
      requiredScopes: [],
    })
    expect(run(document, {}, { user: undefined })).toEqual({
      status: 'unknown',
      requiredScopes: [],
    })
    expect(run(document, {}, { user: true })).toEqual({
      status: 'allowed',
      requiredScopes: [],
    })
  })
})
