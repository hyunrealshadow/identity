import { GraphqlRequestError, identityGraphql } from '#/lib/graphql.server'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'
import { restartAccountSignIn, storeMfaEnrollment } from '#/lib/oauth.server'
import { storeAccountFlash } from '#/lib/oauth-session.server'
import { loadApplicationUrl } from '#/lib/runtime-config.server'

interface BeginTotpEnrollmentResult {
  beginTotpEnrollment: {
    secret: string
    otpAuthUri: string
    enrollmentToken: string
    recoveryCodes: Array<string>
  }
}

export async function handleAccountMfaSetupGet() {
  return new Response(null, {
    status: 303,
    headers: { location: '/account/security?setup=mfa' },
  })
}

export async function handleAccountMfaSetupPost(request: Request) {
  const locale = requestLocale()
  const origin = request.headers.get('origin')
  if (!origin || origin !== new URL(loadApplicationUrl()).origin) {
    await storeAccountFlash({
      error: translate(locale, 'accountInvalidRequestOrigin'),
    })
    return new Response(null, {
      status: 303,
      headers: { location: '/account/security?setup=mfa' },
    })
  }

  try {
    const result = await identityGraphql<BeginTotpEnrollmentResult>(
      `mutation BeginTotpEnrollment {
        beginTotpEnrollment { secret otpAuthUri enrollmentToken recoveryCodes }
      }`,
      undefined,
      { authorization: 'elevated' },
    )
    if (!result) {
      return new Response(null, {
        status: 303,
        headers: {
          location: (
            await restartAccountSignIn('/account/security?setup=mfa')
          ).toString(),
        },
      })
    }
    await storeMfaEnrollment({
      secret: result.beginTotpEnrollment.secret,
      otp_auth_uri: result.beginTotpEnrollment.otpAuthUri,
      enrollment_token: result.beginTotpEnrollment.enrollmentToken,
      recovery_codes: result.beginTotpEnrollment.recoveryCodes,
    })
    await storeAccountFlash({ message: 'saved' })
  } catch (error) {
    await storeAccountFlash({
      error:
        error instanceof GraphqlRequestError
          ? error.message
          : translate(locale, 'temporaryError'),
    })
  }
  return new Response(null, {
    status: 303,
    headers: { location: '/account/security?setup=mfa' },
  })
}
