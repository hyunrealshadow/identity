import type { EnhancedNavigationResponse } from './identity-types'

const ENHANCED_FORM_HEADER = 'x-enhanced-form'

export function navigationResponse(request: Request, destination: string) {
  if (request.headers.get(ENHANCED_FORM_HEADER) === '1') {
    return Response.json({ redirect: destination } satisfies EnhancedNavigationResponse)
  }

  return new Response(null, {
    status: 303,
    headers: { location: destination },
  })
}

export function formErrorResponse(
  request: Request,
  pathname: string,
  message: string,
  values: Record<string, string | undefined>,
) {
  const destination = new URL(pathname, request.url)
  destination.searchParams.set('error', message)

  for (const [key, value] of Object.entries(values)) {
    if (value) destination.searchParams.set(key, value)
  }

  return navigationResponse(request, destination.toString())
}
