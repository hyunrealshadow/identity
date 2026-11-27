import { setResponseStatus } from '@tanstack/react-start/server'

import { finishAuthorization } from '#/lib/oauth.server'

export function acceptsHtml(request: Request): boolean {
  return /(^|,)\s*(\*\/\*|text\/html)/i.test(
    request.headers.get('accept') || '*/*',
  )
}

export async function handleCallbackGet<TNext>({
  request,
  next,
}: {
  request: Request
  next: () => TNext
}): Promise<Response | TNext> {
  const response = await finishAuthorization(request)
  if (response.status === 400 && acceptsHtml(request)) {
    setResponseStatus(400)
    return next()
  }
  return response
}
