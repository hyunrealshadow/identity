import { createServerFn } from '@tanstack/react-start'

export const beginAuthorization = createServerFn({ method: 'GET' }).handler(
  async () => {
    const { prepareAuthorization } = await import('./oauth.server')
    return (await prepareAuthorization()).toString()
  },
)

/**
 * Starts a sign-in for a page that needs a session but has no authorization
 * context of its own, such as the device verification page.
 */
export const beginSignIn = createServerFn({ method: 'GET' })
  .validator((data: { returnTo?: string }) => data)
  .handler(async ({ data }) => {
    const { startSignIn } = await import('./oauth.server')
    return (await startSignIn(data.returnTo)).toString()
  })
