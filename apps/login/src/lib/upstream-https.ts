const HTTPS = 'https'

export function forwardedProtoIsHttps(headers: Headers) {
  const xForwardedProto = headers
    .get('x-forwarded-proto')
    ?.split(',', 1)[0]
    ?.trim()

  if (xForwardedProto !== undefined) {
    return xForwardedProto.toLowerCase() === HTTPS
  }

  return (headers.get('forwarded') ?? '')
    .split(',', 1)[0]
    ?.split(';')
    .some((parameter) => {
      const [name, value] = parameter.trim().split('=', 2)
      return (
        name?.toLowerCase() === 'proto' &&
        value?.trim().replace(/^"|"$/g, '').toLowerCase() === HTTPS
      )
    }) ?? false
}
