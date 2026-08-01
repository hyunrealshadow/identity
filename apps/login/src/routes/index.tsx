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
import { graphqlFieldErrors } from '#/lib/account-errors'
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
import {
  consumeAccountFlash,
  storeAccountFlash,
} from '#/lib/oauth-session.server'

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
        id username email emailVerified givenName familyName nickname createdAt
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
  const flash = await consumeAccountFlash()
  try {
    const [data, mfa] = await Promise.all([
      identityGraphql<AccountData>(ACCOUNT_QUERY),
      mfaUiState(),
    ])
    return { locale, data, mfa, flash, error: undefined }
  } catch (error) {
    return {
      locale,
      data: undefined,
      mfa: { enrollment: undefined, recoveryCodes: undefined },
      flash,
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
  loader: () => loadAccountPage(),
  server: {
    handlers: {
      POST: async ({ request }) => {
        const locale = requestLocale()
        const origin = request.headers.get('origin')
        const credentials = await loadClientCredentials()
        if (
          origin &&
          origin !== new URL(credentials.application_url).origin
        ) {
          return new Response(
            translate(locale, 'accountInvalidRequestOrigin'),
            { status: 403 },
          )
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
                  user { id username givenName familyName nickname }
                }
              }`,
              {
                input: {
                  givenName: nullableFormValue(form, 'given_name'),
                  familyName: nullableFormValue(form, 'family_name'),
                  nickname: nullableFormValue(form, 'nickname'),
                },
              },
            )
          } else if (action === 'update-identifiers') {
            await requireGraphql(
              `mutation UpdateAccountIdentifiers($input: UpdateAccountIdentifiersInput!) {
                updateAccountIdentifiers(input: $input) {
                  user { id username email emailVerified }
                }
              }`,
              {
                input: {
                  username: String(form.get('username') ?? ''),
                  email: String(form.get('email') ?? ''),
                },
              },
              { authorization: 'elevated' },
            )
            await clearElevatedAuthorization()
          } else if (action === 'change-password') {
            const newPassword = String(form.get('new_password') ?? '')
            if (newPassword !== String(form.get('confirm_password') ?? '')) {
              throw new AccountActionError(
                translate(locale, 'accountPasswordMismatch'),
                {
                  confirm_password: translate(
                    locale,
                    'accountPasswordMismatch',
                  ),
                },
              )
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
            if (!mfa.enrollment) {
              throw new AccountActionError(
                translate(locale, 'accountMfaSetupExpired'),
                {
                  code: translate(locale, 'accountMfaSetupExpired'),
                },
              )
            }
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
            return new Response(translate(locale, 'accountUnknownAction'), {
              status: 400,
            })
          }
          await storeAccountFlash({ message: 'saved' })
          return redirectHome()
        } catch (error) {
          if (
            (action === 'change-password' ||
              action === 'update-identifiers' ||
              isMfaAction(action)) &&
            error instanceof GraphqlRequestError &&
            requiresReauthentication(error)
          ) {
            return new Response(null, {
              status: 303,
              headers: {
                location: `/oauth/reauth?purpose=${reauthPurpose(action)}&return_to=%2F`,
              },
            })
          }
          await storeAccountFlash(accountFlashFromError(error, locale))
          return redirectHome()
        }
      },
    },
  },
  component: AccountHome,
})

function AccountHome() {
  const { locale, data, flash, error: loadError } = Route.useLoaderData()
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
        {flash.message ? (
          <Alert status="success">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>
                {flash.message === 'reauthenticated'
                  ? t('accountReauthenticated')
                  : t('accountSaved')}
              </Alert.Title>
            </Alert.Content>
          </Alert>
        ) : null}
        {flash.error ? (
          <Alert status="danger" className="auth-alert">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t('accountRequestFailed')}</Alert.Title>
              <Alert.Description>{flash.error}</Alert.Description>
            </Alert.Content>
          </Alert>
        ) : null}

        <Card className="border border-black/[0.07]">
          <Card.Header>
            <Card.Title>{t('accountIdentifiers')}</Card.Title>
            <Card.Description>
              {account.emailVerified
                ? t('accountEmailVerified')
                : t('accountEmailUnverified')}
            </Card.Description>
          </Card.Header>
          <Card.Content>
            <form method="post" className="grid gap-4 md:grid-cols-2">
              <input type="hidden" name="action" value="update-identifiers" />
              <ProfileField
                name="username"
                label={t('accountUsername')}
                value={account.username}
                error={flash.fields?.username}
                required
              />
              <ProfileField
                name="email"
                label={t('accountEmail')}
                value={account.email}
                error={flash.fields?.email}
                required
              />
              <p className="text-sm text-muted md:col-span-2">
                {t('accountIdentifiersDescription')}
              </p>
              <div className="md:col-span-2">
                <Button type="submit">{t('accountSaveIdentifiers')}</Button>
              </div>
            </form>
          </Card.Content>
        </Card>

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
                error={flash.fields?.given_name}
              />
              <ProfileField
                name="family_name"
                label={t('accountFamilyName')}
                value={account.familyName}
                error={flash.fields?.family_name}
              />
              <ProfileField
                name="nickname"
                label={t('accountNickname')}
                value={account.nickname}
                error={flash.fields?.nickname}
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
                    <TextField
                      isRequired
                      fullWidth
                      isInvalid={Boolean(flash.fields?.code)}
                      name="code"
                    >
                      <Label>{t('otp')}</Label>
                      <Input inputMode="numeric" autoComplete="one-time-code" maxLength={8} placeholder="000000" />
                      <FieldError>{flash.fields?.code}</FieldError>
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
                error={flash.fields?.current_password}
              />
              <PasswordField
                name="new_password"
                label={t('accountNewPassword')}
                error={flash.fields?.new_password}
              />
              <PasswordField
                name="confirm_password"
                label={t('accountConfirmPassword')}
                error={flash.fields?.confirm_password}
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
  error,
  required = false,
}: {
  name: string
  label: string
  value?: string
  error?: string
  required?: boolean
}) {
  return (
    <TextField
      isRequired={required}
      fullWidth
      isInvalid={Boolean(error)}
      name={name}
    >
      <Label>{label}</Label>
      <Input defaultValue={value} />
      <FieldError>{error}</FieldError>
    </TextField>
  )
}

function PasswordField({
  name,
  label,
  error,
}: {
  name: string
  label: string
  error?: string
}) {
  return (
    <TextField isRequired fullWidth isInvalid={Boolean(error)} name={name}>
      <Label>{label}</Label>
      <Input type="password" autoComplete="new-password" />
      <FieldError>{error}</FieldError>
    </TextField>
  )
}

async function requireGraphql<T>(
  query: string,
  variables?: Record<string, unknown>,
  options?: { authorization?: 'default' | 'elevated' },
) {
  const data = await identityGraphql<T>(query, variables, options)
  if (!data) {
    throw new AccountActionError(
      translate(requestLocale(), 'accountAuthenticationRequired'),
    )
  }
  return data
}

class AccountActionError extends Error {
  readonly fields: Record<string, string>

  constructor(message: string, fields: Record<string, string> = {}) {
    super(message)
    this.name = 'AccountActionError'
    this.fields = fields
  }
}

function accountFlashFromError(
  error: unknown,
  locale: string,
): { error: string; fields?: Record<string, string> } {
  if (error instanceof AccountActionError) {
    return { error: error.message, fields: error.fields }
  }
  if (error instanceof GraphqlRequestError) {
    const fields = graphqlFieldErrors(error.errors)
    return {
      error: error.message,
      fields: Object.keys(fields).length ? fields : undefined,
    }
  }
  return {
    error:
      error instanceof Error
        ? error.message
        : translate(locale, 'temporaryError'),
  }
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
  if (action === 'update-identifiers') return 'account'
  return isMfaAction(action) ? 'account' : 'password'
}

function nullableFormValue(form: FormData, name: string) {
  const value = String(form.get(name) ?? '').trim()
  return value || null
}

function redirectHome() {
  return new Response(null, {
    status: 303,
    headers: { location: '/' },
  })
}

function formatDate(value: string, locale: string) {
  return new Intl.DateTimeFormat(locale, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value))
}
