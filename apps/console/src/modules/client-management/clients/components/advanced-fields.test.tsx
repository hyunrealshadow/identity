import { schemaMetadata } from '@identity/graphql-access'
import { fireEvent, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { EffectivePermissions } from '#/lib/workspace'
import { renderWithLocale } from '#/test/render'
import type { ClientMetadataOptions } from '../hooks/use-client-metadata-options'
import { advancedDraftFromClient, type ClientAdvancedDraft } from '../lib/advanced-form'
import type { ClientKeyCoverage } from '../hooks/use-client-key-coverage'
import { ClientAssertionRow, RequestObjectRows, TokenProtectionRows } from './advanced-fields'

const mocks = vi.hoisted(() => ({ permissions: null as EffectivePermissions | null }))
vi.mock('@tanstack/react-router', () => ({
  Link: ({ to, children, ...props }: { to: string; children: React.ReactNode }) => (
    <a href={to} {...props}>
      {children}
    </a>
  ),
}))
vi.mock('#/lib/workspace', () => ({
  useWorkspace: () => ({ status: 'ready', data: { effectivePermissions: mocks.permissions } }),
}))

/** The scopes the provider declares for a mutation, as the console reads them. */
function mutationScopes(field: string) {
  const policies =
    schemaMetadata.types[schemaMetadata.mutationTypeName ?? '']?.fields[field]?.policies ?? []
  return policies.flatMap((policy) => policy.scopes)
}

function permissions(scopes: string[]): EffectivePermissions {
  return {
    effectiveScopes: scopes,
    requestableScopes: [],
    grantedScopes: [],
    authentication: { acr: 'urn:identity:aal2', authTime: null, aal2: true, recent: true },
  }
}

function draft(idTokenSignedResponseAlgs: string[]): ClientAdvancedDraft {
  return {
    ...advancedDraftFromClient({
      frontchannelLogoutSessionRequired: false,
      backchannelLogoutSessionRequired: false,
      contacts: [],
      subjectType: 'PUBLIC',
      requireAuthTime: false,
      defaultAcrValues: [],
      idTokenSignedResponseAlgs: [],
      idTokenEncryptedResponseAlgs: [],
      idTokenEncryptedResponseEncs: [],
      userinfoSignedResponseAlgs: [],
      userinfoEncryptedResponseAlgs: [],
      userinfoEncryptedResponseEncs: [],
      requestObjectSigningAlgs: [],
      requestObjectEncryptionAlgs: [],
      requestObjectEncryptionEncs: [],
      requestUris: [],
      tokenEndpointAuthSigningAlgs: [],
    }),
    idTokenSignedResponseAlgs,
  }
}

const options = {
  idTokenSigningAlgs: ['RS256', 'PS256', 'ES256'],
  activeSigningAlgs: ['ES256'],
  idTokenEncryptionAlgs: [],
  idTokenEncryptionEncs: [],
  userinfoSigningAlgs: [],
  userinfoEncryptionAlgs: [],
  userinfoEncryptionEncs: [],
} as unknown as ClientMetadataOptions

function renderRows(
  selected: string[],
  { onChange = vi.fn(), active = ['ES256'] }: { onChange?: () => void; active?: string[] } = {},
) {
  return renderWithLocale(
    <TokenProtectionRows
      draft={draft(selected)}
      onChange={onChange}
      errors={{}}
      options={{ ...options, activeSigningAlgs: active }}
    />,
  )
}

function chip(value: string) {
  const element = document.querySelector<HTMLElement>(`[data-chip-value="${value}"]`)
  if (!element) throw new Error(`no reorderable chip for ${value}`)
  return element
}

describe('issued signature algorithms', () => {
  beforeEach(() => {
    mocks.permissions = permissions([])
  })

  it('names the algorithm the current keys select', () => {
    renderRows(['RS256', 'ES256'])

    expect(screen.getByText('Currently uses ES256')).toBeTruthy()
    expect(screen.queryByRole('link')).toBeNull()
  })

  it('sends someone who can add signing keys to the key settings', () => {
    mocks.permissions = permissions(mutationScopes('createSigningKey'))
    renderRows(['RS256', 'PS256'])

    expect(
      screen.getByText(/has an active signing key, so ID Tokens cannot be issued\./),
    ).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Manage keys' }).getAttribute('href')).toBe(
      '/settings/signing-keys',
    )
  })

  it('asks someone without key management to contact an administrator', () => {
    renderRows(['RS256', 'PS256'])

    expect(
      screen.getByText(
        'None of the selected algorithms has an active signing key, so ID Tokens cannot be issued. Ask an administrator to add a signing key.',
      ),
    ).toBeTruthy()
    expect(screen.queryByRole('link', { name: 'Manage keys' })).toBeNull()
  })
})

describe('algorithm order', () => {
  beforeEach(() => {
    mocks.permissions = permissions([])
  })

  it('issues with the first algorithm in the administrator\'s order', () => {
    renderRows(['ES256', 'RS256'], { active: ['RS256', 'ES256'] })

    expect(screen.getByText('Currently uses ES256')).toBeTruthy()
  })

  it('moves a chip with Alt and the arrow keys and announces its place', () => {
    const onChange = vi.fn()
    renderRows(['RS256', 'PS256', 'ES256'], { onChange })

    fireEvent.keyDown(chip('ES256'), { key: 'ArrowLeft', altKey: true })

    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ idTokenSignedResponseAlgs: ['RS256', 'ES256', 'PS256'] }),
    )
    expect(screen.getByText('ES256 moved to position 2')).toBeTruthy()
  })

  it('says in the row hint that chips can be reordered once there are two', () => {
    const { unmount } = renderRows(['ES256'])
    expect(screen.queryByText(/Drag the chips to reorder/)).toBeNull()
    unmount()

    renderRows(['ES256', 'RS256'])
    expect(
      screen.getByText(
        'Uses the first listed algorithm that has an active key. Drag the chips to reorder.',
      ),
    ).toBeTruthy()
  })

  it('does not move past either end', () => {
    const onChange = vi.fn()
    renderRows(['RS256', 'ES256'], { onChange })

    fireEvent.keyDown(chip('RS256'), { key: 'ArrowLeft', altKey: true })

    expect(onChange).not.toHaveBeenCalled()
  })

  it('keeps accepted algorithm sets unordered', () => {
    const selected = draft([])
    renderWithLocale(
      <RequestObjectRows
        draft={{ ...selected, requestObjectSigningAlgs: ['RS256', 'ES256'] }}
        onChange={vi.fn()}
        errors={{}}
        options={
          { requestObjectSigningAlgs: ['RS256', 'ES256'] } as unknown as ClientMetadataOptions
        }
      />,
    )

    expect(document.querySelector('[data-chip-value]')).toBeNull()
  })
})

function coverage(
  overrides: Partial<ClientKeyCoverage['coverage']> = {},
  authMethods: ClientKeyCoverage['authMethods'] = ['CLIENT_SECRET_BASIC'],
): ClientKeyCoverage {
  return {
    coverage: {
      encryptionAlgs: [],
      verificationAlgs: [],
      remoteKeys: false,
      secret: true,
      ...overrides,
    },
    authMethods,
  }
}

describe('choices backed by the client\'s own credentials', () => {
  beforeEach(() => {
    mocks.permissions = permissions([])
  })

  function renderEncryption(clientKeys: ClientKeyCoverage | null) {
    return renderWithLocale(
      <TokenProtectionRows
        draft={{ ...draft([]), idTokenEncryptedResponseAlgs: ['RSA-OAEP'] }}
        onChange={vi.fn()}
        errors={{}}
        options={{ ...options, idTokenEncryptionAlgs: ['RSA-OAEP', 'ECDH-ES'] }}
        clientId="Q2xpZW50OkE"
        clientKeys={clientKeys}
      />,
    )
  }

  it('warns when the client has no public key for the response encryption', () => {
    mocks.permissions = permissions(mutationScopes('addClientPublicKey'))
    renderEncryption(coverage({ encryptionAlgs: ['ECDH-ES'] }))

    expect(
      screen.getByText(/no registered encryption key for the selected algorithms, so ID Tokens/),
    ).toBeTruthy()
    expect(
      screen.getByRole('link', { name: 'Manage credentials' }).getAttribute('href'),
    ).toBe('/clients/$clientId/credentials')
  })

  it('names the encryption algorithm a registered key serves', () => {
    renderEncryption(coverage({ encryptionAlgs: ['RSA-OAEP'] }))

    expect(screen.getByText('Currently uses RSA-OAEP')).toBeTruthy()
  })

  it('claims nothing while the client\'s credentials are unknown', () => {
    renderEncryption(null)

    expect(screen.queryByText(/no registered encryption key/)).toBeNull()
    expect(screen.queryByText(/Currently uses/)).toBeNull()
  })

  function renderRequestObjects(selected: string[], clientKeys: ClientKeyCoverage) {
    return renderWithLocale(
      <RequestObjectRows
        draft={{ ...draft([]), requestObjectSigningAlgs: selected }}
        onChange={vi.fn()}
        errors={{}}
        options={
          {
            requestObjectSigningAlgs: ['none', 'RS256', 'ES256'],
            requestObjectEncryptionAlgs: [],
            requestObjectEncryptionEncs: [],
            activeRequestObjectEncryptionAlgs: [],
          } as unknown as ClientMetadataOptions
        }
        clientKeys={clientKeys}
      />,
    )
  }

  it('rejects signed request objects the client has no key to verify', () => {
    renderRequestObjects(['RS256'], coverage({ verificationAlgs: ['ES256'] }))

    expect(screen.getByText(/signed request objects are rejected/)).toBeTruthy()
  })

  it('needs no key for unsigned request objects', () => {
    renderRequestObjects(['none'], coverage())

    expect(screen.queryByText(/request objects are rejected/)).toBeNull()
  })

  function renderAssertion(clientKeys: ClientKeyCoverage) {
    return renderWithLocale(
      <ClientAssertionRow
        draft={{ ...draft([]), tokenEndpointAuthSigningAlgs: ['RS256', 'HS256'] }}
        onChange={vi.fn()}
        errors={{}}
        options={
          { tokenEndpointAuthSigningAlgs: ['RS256', 'ES256', 'HS256'] } as unknown as
            ClientMetadataOptions
        }
        clientKeys={clientKeys}
      />,
    )
  }

  it('checks assertion keys only for the assertion methods the client uses', () => {
    renderAssertion(coverage({ secret: false }, ['CLIENT_SECRET_BASIC']))

    expect(screen.queryByText(/assertion authentication fails/)).toBeNull()
  })

  it('warns when no credential verifies the client\'s assertions', () => {
    renderAssertion(coverage({ secret: false }, ['PRIVATE_KEY_JWT', 'CLIENT_SECRET_JWT']))

    expect(screen.getByText(/assertion authentication fails/)).toBeTruthy()
  })

  it('accepts an HMAC assertion signed with an active client secret', () => {
    renderAssertion(coverage({ secret: true }, ['CLIENT_SECRET_JWT']))

    expect(screen.queryByText(/assertion authentication fails/)).toBeNull()
  })

  it('does not judge keys a JWKS URI provides at verification time', () => {
    renderAssertion(coverage({ remoteKeys: true }, ['PRIVATE_KEY_JWT']))

    expect(screen.queryByText(/assertion authentication fails/)).toBeNull()
  })
})
