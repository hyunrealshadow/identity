import { createServerFn } from '@tanstack/react-start'

/**
 * Start top-level sign-in. `returnTo` is the local page to come back to; the
 * server keeps only same-origin paths. `selectAccount` asks the provider to let
 * the user choose among remembered accounts.
 */
export const beginAuthorization = createServerFn({ method: 'GET' })
  .validator(
    (data: { returnTo?: string; selectAccount?: boolean } | undefined) => data ?? {},
  )
  .handler(async ({ data }) => {
    const { startSignIn } = await import('./oauth.server')
    return (
      await startSignIn(data.returnTo, { selectAccount: data.selectAccount === true })
    ).toString()
  })
