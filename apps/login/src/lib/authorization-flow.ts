import { createServerFn } from '@tanstack/react-start'

export const beginAuthorization = createServerFn({ method: 'GET' }).handler(
  async () => {
    const { prepareAuthorization } = await import('./oauth.server')
    return (await prepareAuthorization()).toString()
  },
)
