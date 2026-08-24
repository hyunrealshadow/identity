import { createFileRoute, redirect } from '@tanstack/react-router'

import { isThemePreference, safeAppearanceReturnTo } from '#/lib/appearance'
import { storeAnonymousThemePreference } from '#/lib/appearance.server'

export const Route = createFileRoute('/appearance')({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const form = await request.formData()
        const theme = form.get('theme')
        if (isThemePreference(theme)) storeAnonymousThemePreference(theme)
        throw redirect({
          href: safeAppearanceReturnTo(request.url, form.get('return_to')),
          statusCode: 303,
        })
      },
    },
  },
})
