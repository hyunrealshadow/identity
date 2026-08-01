export interface GraphqlFieldErrorSource {
  extensions?: {
    fields?: Array<{ field: string; message: string }>
  }
}

export function graphqlFieldErrors(
  errors: ReadonlyArray<GraphqlFieldErrorSource>,
) {
  return Object.fromEntries(
    errors.flatMap(({ extensions }) =>
      (extensions?.fields ?? []).map((field) => [
        htmlFieldName(field.field),
        field.message,
      ]),
    ),
  )
}

export function htmlFieldName(field: string) {
  const names: Record<string, string> = {
    currentPassword: 'current_password',
    newPassword: 'new_password',
    givenName: 'given_name',
    familyName: 'family_name',
  }
  return names[field] ?? field
}
