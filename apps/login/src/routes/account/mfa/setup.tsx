import { createFileRoute } from '@tanstack/react-router'

import { GraphqlRequestError, identityGraphql } from '#/lib/graphql.server'
import { translate } from '#/lib/i18n'
import { requestLocale } from '#/lib/i18n.server'
import { storeMfaEnrollment } from '#/lib/oauth.server'
import { storeAccountFlash } from '#/lib/oauth-session.server'

interface BeginTotpEnrollmentResult {
  beginTotpEnrollment: {
    secret: string
    otpAuthUri: string
    enrollmentToken: string
    recoveryCodes: Array<string>
  }
}

export const Route = createFileRoute('/account/mfa/setup')({
  server: {
    handlers: {
      GET: async () => {
        const locale = requestLocale()
        try {
          const result = await identityGraphql<BeginTotpEnrollmentResult>(
            `mutation BeginTotpEnrollment {
              beginTotpEnrollment { secret otpAuthUri enrollmentToken recoveryCodes }
            }`,
            undefined,
            { authorization: 'elevated' },
          )
          if (!result) {
            throw new Error(translate(locale, 'accountAuthenticationRequired'))
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
              error instanceof GraphqlRequestError || error instanceof Error
                ? error.message
                : translate(locale, 'temporaryError'),
          })
        }
        return new Response(null, {
          status: 303,
          headers: { location: '/account/security?setup=mfa' },
        })
      },
    },
  },
})
