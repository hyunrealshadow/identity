import {
  Alert,
  Button,
  Card,
  FieldError,
  Input,
  Label,
  Table,
  TextField,
} from '@heroui/react'
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import {
  GraphqlRequestError,
  identityGraphql,
} from '#/lib/graphql.server'
import { loadClientCredentials } from '#/lib/client-credentials.server'
import {
  clearElevatedAuthorization,
  clearMfaUiState,
  finishLogout,
  mfaUiState,
  storeMfaEnrollment,
  storeRecoveryCodes,
} from '#/lib/oauth.server'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'

interface AccountData {
  viewer: {
    account: {
      id: string
      username: string
      email: string
      emailVerified: boolean
      givenName?: string
      familyName?: string
      nickname?: string
      phoneNumber?: string
      createdAt: string
    }
    sessions: {
      edges: Array<{
        node: {
          id: string
          status: string
          current: boolean
          deviceName?: string
          deviceType?: string
          osName?: string
          browserName?: string
          ipAddress?: string
          lastActiveAt?: string
          createdAt: string
        }
      }>
    }
    security: {
      totpEnabled: boolean
      recoveryCodesRemaining: number
    }
  }
}

const ACCOUNT_QUERY = `
  query AccountHome {
    viewer {
      account {
        id username email emailVerified givenName familyName nickname
        phoneNumber createdAt
      }
      sessions(first: 50) {
        edges {
          node {
            id status current deviceName deviceType osName browserName
            ipAddress lastActiveAt createdAt
          }
        }
      }
      security { totpEnabled recoveryCodesRemaining }
    }
  }
`

const loadAccountPage = createServerFn({ method: 'GET' }).handler(async () => {
  const locale = requestLocale()
  try {
    const [data, mfa] = await Promise.all([
      identityGraphql<AccountData>(ACCOUNT_QUERY),
      mfaUiState(),
    ])
    return { locale, data, mfa, error: undefined }
  } catch (error) {
    return {
      locale,
      data: undefined,
      mfa: { enrollment: undefined, recoveryCodes: undefined },
      error:
        error instanceof GraphqlRequestError
          ? error.message
          : error instanceof Error
            ? error.message
            : translate(locale, 'temporaryError'),
    }
  }
})

export const Route = createFileRoute('/')({
  validateSearch: (search): { message?: string; error?: string } => ({
    message: typeof search.message === 'string' ? search.message : undefined,
    error: typeof search.error === 'string' ? search.error : undefined,
  }),
  loader: () => loadAccountPage(),
  server: {
    handlers: {
      POST: async ({ request }) => {
        const origin = request.headers.get('origin')
        const credentials = await loadClientCredentials()
        if (
          origin &&
          origin !== new URL(credentials.application_url).origin
        ) {
          return new Response('Invalid request origin', { status: 403 })
        }
        const form = await request.formData()
        const action = String(form.get('action') ?? '')
        try {
          if (action === 'logout') {
            return await finishLogout(credentials.application_url)
          }
          if (action === 'revoke-session') {
            await requireGraphql(
              `mutation RevokeSession($id: ID!) {
                revokeSession(id: $id) { session { id status } }
              }`,
              { id: String(form.get('session_id') ?? '') },
            )
          } else if (action === 'revoke-others') {
            await requireGraphql(
              `mutation RevokeOthers {
                revokeOtherSessions { revokedCount }
              }`,
            )
          } else if (action === 'update-profile') {
            await requireGraphql(
              `mutation UpdateProfile($input: UpdateProfileInput!) {
                updateProfile(input: $input) {
                  user { id username givenName familyName nickname phoneNumber }
                }
              }`,
              {
                input: {
                  givenName: nullableFormValue(form, 'given_name'),
                  familyName: nullableFormValue(form, 'family_name'),
                  nickname: nullableFormValue(form, 'nickname'),
                  phoneNumber: nullableFormValue(form, 'phone_number'),
                },
              },
            )
          } else if (action === 'change-password') {
            const newPassword = String(form.get('new_password') ?? '')
            if (newPassword !== String(form.get('confirm_password') ?? '')) {
              throw new Error('Passwords do not match')
            }
            await requireGraphql(
              `mutation ChangePassword($input: ChangePasswordInput!) {
                changePassword(input: $input) { changed }
              }`,
              {
                input: {
                  currentPassword: String(form.get('current_password') ?? ''),
                  newPassword,
                },
              },
              { authorization: 'elevated' },
            )
            await clearElevatedAuthorization()
          } else if (action === 'begin-totp') {
            const data = await requireGraphql<{
              beginTotpEnrollment: {
                secret: string
                otpauthUri: string
                enrollmentToken: string
              }
            }>(
              `mutation BeginTotpEnrollment {
                beginTotpEnrollment {
                  secret otpauthUri enrollmentToken
                }
              }`,
              undefined,
              { authorization: 'elevated' },
            )
            await storeMfaEnrollment({
              secret: data.beginTotpEnrollment.secret,
              otpauth_uri: data.beginTotpEnrollment.otpauthUri,
              enrollment_token: data.beginTotpEnrollment.enrollmentToken,
            })
          } else if (action === 'confirm-totp') {
            const mfa = await mfaUiState()
            if (!mfa.enrollment) throw new Error('Authenticator setup expired')
            const data = await requireGraphql<{
              confirmTotpEnrollment: { recoveryCodes: Array<string> }
            }>(
              `mutation ConfirmTotpEnrollment($input: ConfirmTotpEnrollmentInput!) {
                confirmTotpEnrollment(input: $input) { recoveryCodes }
              }`,
              {
                input: {
                  enrollmentToken: mfa.enrollment.enrollment_token,
                  code: String(form.get('code') ?? ''),
                },
              },
              { authorization: 'elevated' },
            )
            await storeRecoveryCodes(
              data.confirmTotpEnrollment.recoveryCodes,
            )
            await clearElevatedAuthorization()
          } else if (action === 'disable-totp') {
            await requireGraphql(
              `mutation DisableTotp { disableTotp { changed } }`,
              undefined,
              { authorization: 'elevated' },
            )
            await clearMfaUiState()
            await clearElevatedAuthorization()
          } else if (action === 'regenerate-recovery-codes') {
            const data = await requireGraphql<{
              regenerateRecoveryCodes: { recoveryCodes: Array<string> }
            }>(
              `mutation RegenerateRecoveryCodes {
                regenerateRecoveryCodes { recoveryCodes }
              }`,
              undefined,
              { authorization: 'elevated' },
            )
            await storeRecoveryCodes(
              data.regenerateRecoveryCodes.recoveryCodes,
            )
            await clearElevatedAuthorization()
          } else if (action === 'acknowledge-recovery-codes') {
            await clearMfaUiState()
          } else {
            return new Response('Unknown action', { status: 400 })
          }
          return redirectWith('message', 'saved')
        } catch (error) {
          if (
            (action === 'change-password' || isMfaAction(action)) &&
            error instanceof GraphqlRequestError &&
            requiresReauthentication(error)
          ) {
            return new Response(null, {
              status: 303,
              headers: {
                location: `/oauth/reauth?purpose=${reauthPurpose(action)}&return_to=%2F%3Fmessage%3Dreauthenticated`,
              },
            })
          }
          return redirectWith(
            'error',
            error instanceof Error ? error.message : 'Request failed',
          )
        }
      },
    },
  },
  component: AccountHome,
})

function AccountHome() {
  const { locale, data, error: loadError } = Route.useLoaderData()
  const search = Route.useSearch()
  const t = (
    key: Parameters<typeof translate>[1],
    values?: Parameters<typeof translate>[2],
  ) => translate(locale, key, values)
  const account = data?.viewer.account
  const sessions = data?.viewer.sessions.edges.map((edge) => edge.node) ?? []
  const security = data?.viewer.security

  if (!account) {
    return (
      <main
        lang={locale}
        className="auth-background flex min-h-screen items-center justify-center px-6"
      >
        <Card className="auth-card w-full max-w-lg border border-black/[0.07] bg-white p-8 text-center">
          <Card.Header>
            <Card.Title className="text-2xl">{t('accountWelcome')}</Card.Title>
            <Card.Description>{t('accountSignInDescription')}</Card.Description>
          </Card.Header>
          {loadError ? (
            <Alert status="danger" className="auth-alert">
              <Alert.Indicator />
              <Alert.Content>
                <Alert.Title>{t('unableToContinue')}</Alert.Title>
                <Alert.Description>{loadError}</Alert.Description>
              </Alert.Content>
            </Alert>
          ) : null}
          <Card.Footer className="mt-4">
            <a
              href="/oauth/start"
              className="inline-flex h-10 w-full items-center justify-center rounded-field bg-accent px-4 font-medium text-accent-foreground"
            >
              {t('accountSignIn')}
            </a>
          </Card.Footer>
        </Card>
      </main>
    )
  }

  return (
    <main lang={locale} className="min-h-screen bg-background">
      <header className="border-b border-separator bg-surface">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div>
            <p className="text-sm text-muted">{t('accountConsole')}</p>
            <h1 className="text-xl font-semibold">{account.username}</h1>
          </div>
          <form method="post">
            <input type="hidden" name="action" value="logout" />
            <Button type="submit" variant="secondary">
              {t('accountSignOut')}
            </Button>
          </form>
        </div>
      </header>

      <div className="mx-auto grid max-w-6xl gap-6 px-6 py-8">
        {search.message ? (
          <Alert status="success">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>
                {search.message === 'reauthenticated'
                  ? t('accountReauthenticated')
                  : t('accountSaved')}
              </Alert.Title>
            </Alert.Content>
          </Alert>
        ) : null}
        {search.error ? (
          <Alert status="danger" className="auth-alert">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('accountRequestFailed')}</Alert.Title>
              <Alert.Description>{search.error}</Alert.Description>
            </Alert.Content>
          </Alert>
        ) : null}

        <Card className="border border-black/[0.07]">
          <Card.Header>
            <Card.Title>{t('accountProfile')}</Card.Title>
            <Card.Description>{account.email}</Card.Description>
          </Card.Header>
          <Card.Content>
            <form method="post" className="grid gap-4 md:grid-cols-2">
              <input type="hidden" name="action" value="update-profile" />
              <ProfileField
                name="given_name"
                label={t('accountGivenName')}
                value={account.givenName}
              />
              <ProfileField
                name="family_name"
                label={t('accountFamilyName')}
                value={account.familyName}
              />
              <ProfileField
                name="nickname"
                label={t('accountNickname')}
                value={account.nickname}
              />
              <ProfileField
                name="phone_number"
                label={t('accountPhone')}
                value={account.phoneNumber}
              />
              <div className="md:col-span-2">
                <Button type="submit">{t('accountSaveProfile')}</Button>
              </div>
            </form>
          </Card.Content>
        </Card>

        {security ? (
          <Card className="border border-black/[0.07]">
            <Card.Header>
              <Card.Title>{t('accountMfa')}</Card.Title>
              <Card.Description>{t('accountMfaDescription')}</Card.Description>
            </Card.Header>
            <Card.Content className="space-y-5">
              {mfa.recoveryCodes?.length ? (
                <Alert status="warning">
                  <Alert.Indicator />
                  <Alert.Content>
                    <Alert.Title>{t('accountRecoveryCodesTitle')}</Alert.Title>
                    <Alert.Description>
                      {t('accountRecoveryCodesDescription')}
                    </Alert.Description>
                    <div className="mt-4 grid gap-2 sm:grid-cols-2">
                      {mfa.recoveryCodes.map((code) => (
                        <code key={code} className="rounded-field bg-surface-secondary px-3 py-2 font-mono text-sm">
                          {code}
                        </code>
                      ))}
                    </div>
                    <form method="post" className="mt-4">
                      <input type="hidden" name="action" value="acknowledge-recovery-codes" />
                      <Button type="submit">{t('accountRecoveryCodesSaved')}</Button>
                    </form>
                  </Alert.Content>
                </Alert>
              ) : null}

              {mfa.enrollment ? (
                <div className="grid max-w-xl gap-4">
                  <p className="text-sm text-muted">{t('accountMfaSetupDescription')}</p>
                  <div className="rounded-field bg-surface-secondary p-4">
                    <p className="text-xs font-medium text-muted">{t('accountMfaSecret')}</p>
                    <code className="mt-1 block break-all font-mono">{mfa.enrollment.secret}</code>
                    <a className="auth-link mt-3 inline-block text-sm font-semibold text-accent" href={mfa.enrollment.otpauth_uri}>
                      {t('accountMfaOpenAuthenticator')}
                    </a>
                  </div>
                  <form method="post" className="grid gap-3">
                    <input type="hidden" name="action" value="confirm-totp" />
                    <TextField isRequired fullWidth name="code">
                      <Label>{t('otp')}</Label>
                      <Input inputMode="numeric" autoComplete="one-time-code" maxLength={8} placeholder="000000" />
                      <FieldError />
                    </TextField>
                    <Button type="submit">{t('accountMfaConfirm')}</Button>
                  </form>
                </div>
              ) : security.totpEnabled ? (
                <div className="space-y-4">
                  <p className="text-sm text-muted">
                    {t('accountMfaEnabled')} · {t('accountRecoveryCodesRemaining', { count: security.recoveryCodesRemaining })}
                  </p>
                  <div className="flex flex-wrap gap-3">
                    <form method="post">
                      <input type="hidden" name="action" value="regenerate-recovery-codes" />
                      <Button type="submit" variant="secondary">{t('accountRegenerateRecoveryCodes')}</Button>
                    </form>
                    <form method="post">
                      <input type="hidden" name="action" value="disable-totp" />
                      <Button type="submit" variant="danger">{t('accountMfaDisable')}</Button>
                    </form>
                  </div>
                </div>
              ) : (
                <form method="post">
                  <input type="hidden" name="action" value="begin-totp" />
                  <Button type="submit">{t('accountMfaEnable')}</Button>
                </form>
              )}
            </Card.Content>
          </Card>
        ) : null}

        <Card className="border border-black/[0.07]">
          <Card.Header>
            <Card.Title>{t('accountSessions')}</Card.Title>
            <Card.Description>{t('accountSessionsDescription')}</Card.Description>
          </Card.Header>
          <Card.Content className="space-y-4">
            <Table variant="secondary">
              <Table.ScrollContainer>
                <Table.Content aria-label={t('accountSessions')}>
                  <Table.Header>
                    <Table.Column isRowHeader>{t('accountDevice')}</Table.Column>
                    <Table.Column>{t('accountLastActive')}</Table.Column>
                    <Table.Column>{t('accountIpAddress')}</Table.Column>
                    <Table.Column>{t('accountAction')}</Table.Column>
                  </Table.Header>
                  <Table.Body items={sessions}>
                    {(session) => (
                      <Table.Row id={session.id}>
                        <Table.Cell>
                          <div className="font-medium">
                            {session.deviceName ??
                              session.browserName ??
                              t('accountUnknownDevice')}
                          </div>
                          <div className="text-xs text-muted">
                            {[session.osName, session.deviceType]
                              .filter(Boolean)
                              .join(' · ')}
                            {session.current ? ` · ${t('accountCurrent')}` : ''}
                          </div>
                        </Table.Cell>
                        <Table.Cell>
                          {formatDate(
                            session.lastActiveAt ?? session.createdAt,
                            locale,
                          )}
                        </Table.Cell>
                        <Table.Cell>{session.ipAddress ?? '—'}</Table.Cell>
                        <Table.Cell>
                          {session.current ? (
                            <span className="text-sm text-muted">
                              {t('accountCurrent')}
                            </span>
                          ) : (
                            <form method="post">
                              <input
                                type="hidden"
                                name="action"
                                value="revoke-session"
                              />
                              <input
                                type="hidden"
                                name="session_id"
                                value={session.id}
                              />
                              <Button type="submit" size="sm" variant="danger">
                                {t('accountRevoke')}
                              </Button>
                            </form>
                          )}
                        </Table.Cell>
                      </Table.Row>
                    )}
                  </Table.Body>
                </Table.Content>
              </Table.ScrollContainer>
            </Table>
            <form method="post">
              <input type="hidden" name="action" value="revoke-others" />
              <Button type="submit" variant="danger">
                {t('accountRevokeOthers')}
              </Button>
            </form>
          </Card.Content>
        </Card>

        <Card className="border border-black/[0.07]">
          <Card.Header>
            <Card.Title>{t('accountPassword')}</Card.Title>
            <Card.Description>{t('accountPasswordDescription')}</Card.Description>
          </Card.Header>
          <Card.Content>
            <form method="post" className="grid max-w-xl gap-4">
              <input type="hidden" name="action" value="change-password" />
              <PasswordField
                name="current_password"
                label={t('accountCurrentPassword')}
              />
              <PasswordField
                name="new_password"
                label={t('accountNewPassword')}
              />
              <PasswordField
                name="confirm_password"
                label={t('accountConfirmPassword')}
              />
              <Button type="submit">{t('accountChangePassword')}</Button>
            </form>
          </Card.Content>
        </Card>
      </div>
    </main>
  )
}

function ProfileField({
  name,
  label,
  value,
}: {
  name: string
  label: string
  value?: string
}) {
  return (
    <TextField fullWidth name={name}>
      <Label>{label}</Label>
      <Input defaultValue={value} />
      <FieldError />
    </TextField>
  )
}

function PasswordField({ name, label }: { name: string; label: string }) {
  return (
    <TextField isRequired fullWidth name={name}>
      <Label>{label}</Label>
      <Input type="password" autoComplete="new-password" />
      <FieldError />
    </TextField>
  )
}

async function requireGraphql<T>(
  query: string,
  variables?: Record<string, unknown>,
  options?: { authorization?: 'default' | 'elevated' },
) {
  const data = await identityGraphql<T>(query, variables, options)
  if (!data) throw new Error('Authentication is required')
  return data
}

function requiresReauthentication(error: GraphqlRequestError) {
  return error.errors.some(
    ({ extensions }) =>
      extensions?.code === 'FRESH_AUTHENTICATION_REQUIRED' ||
      extensions?.requiredScope === 'password.change',
  )
}

function isMfaAction(action: string) {
  return [
    'begin-totp',
    'confirm-totp',
    'disable-totp',
    'regenerate-recovery-codes',
  ].includes(action)
}

function reauthPurpose(action: string) {
  if (
    action === 'disable-totp' ||
    action === 'regenerate-recovery-codes'
  ) {
    return 'mfa'
  }
  return isMfaAction(action) ? 'account' : 'password'
}

function nullableFormValue(form: FormData, name: string) {
  const value = String(form.get(name) ?? '').trim()
  return value || null
}

function redirectWith(name: 'message' | 'error', value: string) {
  const location = new URL('/', 'https://local.invalid')
  location.searchParams.set(name, value)
  return new Response(null, {
    status: 303,
    headers: { location: `${location.pathname}${location.search}` },
  })
}

function formatDate(value: string, locale: string) {
  return new Intl.DateTimeFormat(locale, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value))
}
