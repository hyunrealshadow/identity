import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import { requestLocale } from '#/lib/i18n.server'
import { consumeFormFlash } from '#/lib/responses.server'
import { submitDevicePost } from '#/modules/device/lib/device-route.server'
import { loadDeviceVerification } from '#/modules/device/lib/device-verification.server'
import {
  DevicePageView,
  type DeviceSearch,
} from '#/modules/device/pages/device-page'

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadDevicePage = createServerFn({ method: 'GET' })
  .validator(
    (data: { userCode: string; loginId: string; uiLocales?: string }) => data,
  )
  .handler(async ({ data }) => {
    const flash = consumeFormFlash('/device')
    const loginId = data.loginId || flash?.values.login_id || ''
    const uiLocales = data.uiLocales ?? ''
    const locale = requestLocale(uiLocales.split(' '))
    const codeError =
      flash?.fields?.user_code ??
      (flash?.field === 'user_code' ? flash.message : undefined)
    const pageError = codeError ? undefined : flash?.message

    // Without a bound interaction the page is the code form. A code carried
    // by the link (`verification_uri_complete`) is only prefilled: the user
    // must confirm it matches the device before the request is started, so a
    // link sent by someone else cannot start a sign-in by being opened.
    if (!loginId) {
      return {
        device: undefined,
        userCode: flash?.values.user_code || data.userCode,
        prefilled: !flash && !!data.userCode,
        locale,
        uiLocales,
        error: pageError,
        codeError,
      }
    }

    const lookup = await loadDeviceVerification(loginId, locale)
    return {
      device: lookup.status === 'described' ? lookup.description : undefined,
      userCode: '',
      prefilled: false,
      locale,
      uiLocales,
      error: pageError ?? (lookup.status === 'failed' ? lookup.message : undefined),
      codeError,
    }
  })

export const Route = createFileRoute('/device')({
  validateSearch: (search): DeviceSearch => ({
    login_id: optionalString(search.login_id),
    user_code: optionalString(search.user_code),
    error: optionalString(search.error),
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({
    loginId: search.login_id ?? '',
    userCode: search.user_code ?? '',
    uiLocales: search.ui_locales,
  }),
  loader: ({ deps }) => {
    return loadDevicePage({ data: deps })
  },
  server: {
    handlers: {
      POST: ({ request }) => submitDevicePost(request),
    },
  },
  component: DeviceRoute,
})

function DeviceRoute() {
  const search = Route.useSearch()
  const data = Route.useLoaderData()
  return <DevicePageView data={data} search={search} />
}
