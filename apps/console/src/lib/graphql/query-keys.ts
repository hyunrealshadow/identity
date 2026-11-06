import { graphqlDocumentText, type DocumentSource } from './transport'

/** Any generated document; the operation name is read from its text. */
// Generated documents are invariant in their result and variables.
export type AnyDocument = string | DocumentSource<any, any>

const OPERATION_PATTERN = /\b(?:query|mutation|subscription)\s+([_A-Za-z][_0-9A-Za-z]*)/

const names = new Map<string, string>()

/**
 * The operation a document declares. Generated documents carry exactly one
 * named operation, so callers never restate the name next to the document.
 */
export function operationNameOf(document: AnyDocument): string {
  const text = graphqlDocumentText(document)
  const cached = names.get(text)
  if (cached) return cached
  const name = OPERATION_PATTERN.exec(text)?.[1]
  if (!name) throw new Error('GraphQL document has no named operation')
  names.set(text, name)
  return name
}

export type ConsoleQueryKey<TVariables> = readonly [
  'console',
  number,
  string,
  string,
  TVariables | null,
]

/**
 * The single source of console read keys. Every key is scoped by session
 * version and locale, so invalidation, version patches and placeholders never
 * cross an account or a server-rendered language.
 */
export const consoleQueryKeys = {
  /** Every read of one session and locale. */
  scope: (sessionVersion: number, locale: string) =>
    ['console', sessionVersion, locale] as const,
  /** Every variable combination of one read operation. */
  operation: (sessionVersion: number, locale: string, document: AnyDocument) =>
    ['console', sessionVersion, locale, operationNameOf(document)] as const,
  /** One read with its variables. */
  read: <TVariables>(
    sessionVersion: number,
    locale: string,
    document: AnyDocument,
    variables: TVariables | null,
  ): ConsoleQueryKey<TVariables> => [
    'console',
    sessionVersion,
    locale,
    operationNameOf(document),
    variables,
  ],
}

/** The operation segment of a console key, if the key is one. */
export function operationOfKey(key: readonly unknown[]): string | undefined {
  return key[0] === 'console' && typeof key[3] === 'string' ? key[3] : undefined
}
