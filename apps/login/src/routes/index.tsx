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
import { finishLogout } from '#/lib/oauth.server'
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
    }
  }
`

const loadAccountPage = createServerFn({ method: 'GET' }).handler(async () => {
  const locale = requestLocale()
  try {
    const data = await identityGraphql<AccountData>(ACCOUNT_QUERY)
    return { locale, data, error: undefined }
  } catch (error) {
    return {
      locale,
      data: undefined,
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
            return finishLogout(credentials.application_url)
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
            )
          } else {
            return new Response('Unknown action', { status: 400 })
          }
          return redirectWith('message', 'saved')
        } catch (error) {
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
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)
  const account = data?.viewer.account
  const sessions = data?.viewer.sessions.edges.map((edge) => edge.node) ?? []

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
              <Alert.Title>{t('accountSaved')}</Alert.Title>
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
) {
  const data = await identityGraphql<T>(query, variables)
  if (!data) throw new Error('Authentication is required')
  return data
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
