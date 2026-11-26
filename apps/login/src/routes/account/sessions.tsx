import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import {
  fetchAccountSessions,
  type AccountSessionsSearch,
} from '#/modules/account/lib/sessions-route.server'
import { SessionsPageView } from '#/modules/account/pages/sessions-page'

function normalizeAccountSessionsSearch(
  raw: Record<string, unknown>,
): AccountSessionsSearch {
  const after =
    typeof raw.after === 'string' && raw.after.trim() ? raw.after.trim() : undefined
  const before =
    !after && typeof raw.before === 'string' && raw.before.trim()
      ? raw.before.trim()
      : undefined
  return { after, before }
}

const loadAccountSessions = createServerFn({ method: 'GET' })
  .validator((input: AccountSessionsSearch) => input)
  .handler(({ data }) => fetchAccountSessions(data))

export const Route = createFileRoute('/account/sessions')({
  validateSearch: (search: Record<string, unknown>): AccountSessionsSearch =>
    normalizeAccountSessionsSearch(search),
  loaderDeps: ({ search }) => ({
    after: search.after,
    before: search.before,
  }),
  loader: async ({ deps }) => ({
    sessions: await loadAccountSessions({ data: deps }),
  }),
  component: SessionsRoute,
})

function SessionsRoute() {
  const { sessions } = Route.useLoaderData()
  return <SessionsPageView sessionsConnection={sessions} />
}
