import { createFileRoute, redirect } from '@tanstack/react-router'

export const Route = createFileRoute('/')({
  loaderDeps: ({ search }) => ({ uiLocales: search.ui_locales }),
  loader: ({ deps }) => {
    throw redirect({ to: '/account/profile', search: { ui_locales: deps.uiLocales } })
  },
})
