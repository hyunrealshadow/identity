import type { GraphQLFailure } from '#/lib/graphql/transport'
import type { MessageKey } from '#/lib/i18n'

export function failureTitleKey(
  failure: GraphQLFailure | undefined,
  forbidden = false,
): MessageKey {
  if (forbidden) return 'forbiddenTitle'
  switch (failure?.kind) {
    case 'network':
      return 'networkErrorTitle'
    case 'http':
      return 'httpErrorTitle'
    case 'invalid_response':
      return 'invalidResponseTitle'
    case 'unauthorized':
      return 'unauthorizedTitle'
    default:
      return failure ? 'errorTitle' : 'errorTitle'
  }
}

export function failureDescriptionKey(
  failure: GraphQLFailure | undefined,
  forbidden = false,
): MessageKey {
  if (forbidden) return 'forbiddenDescription'
  switch (failure?.kind) {
    case 'network':
      return 'networkErrorDescription'
    case 'http':
      return 'httpErrorDescription'
    case 'invalid_response':
      return 'invalidResponseDescription'
    case 'unauthorized':
      return 'unauthorizedDescription'
    default:
      return 'errorDescriptionFallback'
  }
}
