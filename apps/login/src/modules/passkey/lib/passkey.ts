export const MAX_PASSKEYS_PER_ACCOUNT = 5

export interface PasskeyOptions {
  challenge_id: string
  public_key: Record<string, unknown>
}

export function passkeysSupported() {
  return typeof window !== 'undefined' && window.isSecureContext &&
    typeof PublicKeyCredential !== 'undefined' && !!navigator.credentials
}

function decode(value: string): ArrayBuffer {
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'))
  return Uint8Array.from(binary, (char) => char.charCodeAt(0)).buffer
}

function encode(value: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(value)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

type DescriptorJSON = Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string }
function descriptor(value: DescriptorJSON): PublicKeyCredentialDescriptor {
  return { ...value, id: decode(value.id) }
}

export function authenticationOptions(options: Record<string, unknown>): PublicKeyCredentialRequestOptions {
  const value = options as Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> & {
    challenge: string; allowCredentials?: Array<DescriptorJSON>
  }
  // Keep the server's account-specific allow-list; never request discoverable login.
  if (!value.allowCredentials?.length) throw new Error('Missing account credentials')
  return { ...value, challenge: decode(value.challenge), allowCredentials: value.allowCredentials.map(descriptor), userVerification: 'required' }
}

export function registrationOptions(options: Record<string, unknown>): PublicKeyCredentialCreationOptions {
  const value = options as Omit<PublicKeyCredentialCreationOptions, 'challenge' | 'user' | 'excludeCredentials'> & {
    challenge: string; user: Omit<PublicKeyCredentialUserEntity, 'id'> & { id: string }; excludeCredentials?: Array<DescriptorJSON>
  }
  return { ...value, challenge: decode(value.challenge), user: { ...value.user, id: decode(value.user.id) }, excludeCredentials: value.excludeCredentials?.map(descriptor) }
}

export function serializeCredential(credential: PublicKeyCredential) {
  const response = credential.response
  const base = {
    id: credential.id,
    rawId: encode(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: credential.authenticatorAttachment,
  }
  if ('attestationObject' in response) {
    const registration = response as AuthenticatorAttestationResponse
    return { ...base, response: { clientDataJSON: encode(response.clientDataJSON), attestationObject: encode(registration.attestationObject), transports: registration.getTransports?.() ?? [] } }
  }
  const assertion = response as AuthenticatorAssertionResponse
  return { ...base, response: { clientDataJSON: encode(response.clientDataJSON), authenticatorData: encode(assertion.authenticatorData), signature: encode(assertion.signature), userHandle: assertion.userHandle ? encode(assertion.userHandle) : null } }
}

export async function createPasskey(options: PasskeyOptions, signal?: AbortSignal) {
  const credential = await navigator.credentials.create({ publicKey: registrationOptions(options.public_key), signal })
  if (!credential) throw new DOMException('Cancelled', 'NotAllowedError')
  return serializeCredential(credential as PublicKeyCredential)
}

export async function getPasskey(options: PasskeyOptions, signal?: AbortSignal) {
  const credential = await navigator.credentials.get({ publicKey: authenticationOptions(options.public_key), signal })
  if (!credential) throw new DOMException('Cancelled', 'NotAllowedError')
  return { challenge_id: options.challenge_id, credential: serializeCredential(credential as PublicKeyCredential) }
}
