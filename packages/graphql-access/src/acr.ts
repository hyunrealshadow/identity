/**
 * Authentication context classes (OpenID Connect `acr`) the provider
 * establishes, weakest first. Mirrors `AuthenticationContextClass` in
 * `src/domain/auth/acr.rs`; frontends reference these instead of literals.
 */
export const AuthenticationContextClass = {
  /** One factor: a password. */
  SingleFactor: 'aal1',
  /** Two distinct factors: password plus a one-time or recovery code, or a passkey. */
  MultiFactor: 'aal2',
  /** OpenID EAP ACR Values `phr`: a user-verified passkey. */
  PhishingResistant: 'phr',
} as const

export type AuthenticationContextClass =
  (typeof AuthenticationContextClass)[keyof typeof AuthenticationContextClass]

const STRENGTH: readonly string[] = [
  AuthenticationContextClass.SingleFactor,
  AuthenticationContextClass.MultiFactor,
  AuthenticationContextClass.PhishingResistant,
]

/** Whether an established `acr` meets `required`; a stronger class meets every weaker one. */
export function acrSatisfies(
  established: string | undefined,
  required: AuthenticationContextClass,
): boolean {
  if (established === undefined) return false
  const rank = STRENGTH.indexOf(established)
  return rank >= 0 && rank >= STRENGTH.indexOf(required)
}
