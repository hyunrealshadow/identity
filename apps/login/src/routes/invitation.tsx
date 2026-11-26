import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import { errorMessage } from '#/lib/identity.server'
import type { InvitationCheckResponse } from '#/lib/identity-types'
import { requestLocale } from '#/lib/i18n.server'
import { consumeFormFlash } from '#/lib/responses.server'
import {
  INVITATION_PATH,
  submitInvitationPost,
} from '#/modules/auth/lib/invitation-route.server'
import { checkInvitation } from '#/modules/auth/lib/invitation.server'
import { InvitationPageView } from '#/modules/auth/pages/invitation-page'

interface InvitationSearch {
  token?: string
  ui_locales?: string
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadInvitationPage = createServerFn({ method: 'GET' })
  .validator((data: { token: string; uiLocales?: string }) => data)
  .handler(async ({ data }) => {
    const flash = consumeFormFlash(INVITATION_PATH)
    const uiLocales = data.uiLocales ?? ''
    const locale = requestLocale(uiLocales.split(' '))
    const page = {
      locale,
      uiLocales,
      token: data.token,
      account: undefined as InvitationCheckResponse | undefined,
      error: flash?.fields ? undefined : flash?.message,
      fields: flash?.fields ?? {},
      linkError: undefined as string | undefined,
    }
    if (!data.token) return page
    try {
      page.account = await checkInvitation(data.token, locale)
    } catch (error) {
      page.linkError = errorMessage(error, locale)
    }
    return page
  })

/**
 * Where an emailed invitation link lands. Opening the link only shows the
 * account; the password is set when the form is submitted, so a mail
 * scanner that fetches the link cannot use it. No session is needed, so the
 * link also works on another device.
 */
export const Route = createFileRoute('/invitation')({
  validateSearch: (search): InvitationSearch => ({
    token: optionalString(search.token),
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({
    token: search.token ?? '',
    uiLocales: search.ui_locales,
  }),
  loader: ({ deps }) => loadInvitationPage({ data: deps }),
  headers: () => ({
    'Cache-Control': 'no-store',
    // The token is in this page's address; never pass it on.
    'Referrer-Policy': 'no-referrer',
  }),
  server: {
    handlers: {
      POST: ({ request }) => submitInvitationPost(request),
    },
  },
  component: InvitationRoute,
})

function InvitationRoute() {
  const data = Route.useLoaderData()
  return <InvitationPageView data={data} />
}
