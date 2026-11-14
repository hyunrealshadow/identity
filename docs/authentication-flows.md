# Authentication flows

[Documentation index](README.md) · [Protocol reference](protocol.md) · [Authorization model](authorization.md) · [Security](security.md)

This page traces how a browser or a device becomes a session, how that session
becomes a grant, and how a grant becomes a token. Two layers meet here:

- The **protocol layer** validates an authorization request, issues codes and
  tokens, and enforces the client policy in [protocol.md](protocol.md).
- The **login interaction** is the staged form flow served by
  [Login](../apps/login/README.md). It collects credentials, decides whether a
  session may exist yet, and records which account and consent decision the
  request is bound to.

Policy about what a token may then do lives in
[authorization.md](authorization.md). Assurance levels, freshness windows, and
session rules are summarized in [security.md](security.md).

- [Where each step happens](#where-each-step-happens)
- [The login interaction](#the-login-interaction)
- [Credential stages](#credential-stages)
- [Assurance and freshness](#assurance-and-freshness)
- [Sessions and account selection](#sessions-and-account-selection)
- [Consent](#consent)
- [Continue and code issuance](#continue-and-code-issuance)
- [Refreshing tokens](#refreshing-tokens)
- [Device authorization](#device-authorization)
- [Reauthentication for API calls](#reauthentication-for-api-calls)
- [Logout and session termination](#logout-and-session-termination)
- [Diagnostics](#diagnostics)

## Where each step happens

| Step | Endpoint | Owner |
| --- | --- | --- |
| Authorization request | `GET`/`POST /oauth2/authorize` | Protocol layer |
| Sign-in stages | `GET /login`, `POST /api/auth/login/*`, `POST /api/auth/login/challenge` | Login |
| Consent | `GET /consent`, `POST /oauth2/consent` | Login and protocol layer |
| Return to the protocol | `GET /oauth2/continue` | Protocol layer |
| Code or device redemption | `POST /oauth2/token` | Protocol layer |
| Device verification entry | `GET /device`, `POST /oauth2/device` | Login and protocol layer |
| RP-initiated logout | `GET`/`POST /openid/logout` | Protocol layer |
| Back-channel and front-channel logout | client `backchannel_logout_uri` / `frontchannel_logout_uri` | Protocol layer |

The browser never receives a token from the sign-in pages. Those pages return a
protected session identifier and a continue URI; the code stays inside the
protocol layer.

## The login interaction

An authorization request that needs a user opens an interaction identified by an
encrypted `login_id`. The identifier is not a session and carries no authority on
its own; it only lets the next stage find the stored request, the selected
client, and the requested authentication context.

```text
Created ─▶ IdentifierVerified ─▶ MfaRequired ─▶ Authenticated
                 │                    │
                 ├─▶ MfaEnrollmentRequired ─▶ (enrollment) ─▶ Authenticated
                 └─▶ Expired / Failed (terminal until a restart)
```

| Status | Meaning | What may follow |
| --- | --- | --- |
| `Created` | Interaction opened, no identifier accepted yet | Identifier submission |
| `IdentifierVerified` | User identified, password not yet accepted | Password, passkey |
| `MfaRequired` | Password accepted, a second factor is still required | OTP, recovery code, passkey |
| `MfaEnrollmentRequired` | Password accepted for an AAL2 request, but the user has no second factor | Enrollment, then a completed session |
| `Authenticated` | Session established and bound to the interaction | Continue to consent or the protocol |
| `Expired` | Interaction lifetime elapsed | Restart only |
| `Failed` | Bounded failure such as a locked or disabled account | Nothing |

Rules that keep the stages honest:

- **No session before the second factor.** When a second factor is required, the
  password stage records `MfaRequired` but creates no session. A session appears
  only when the credential stage that completes the flow succeeds.
- **Account switching has a narrow window.** An interaction may switch accounts
  only while it is at `IdentifierVerified`, `MfaRequired`, or
  `MfaEnrollmentRequired`, and never when the interaction was opened as forced
  reauthentication. A restart is allowed only from `Expired` and keeps the
  already-selected account, so it cannot become an account switch.
- **Failures are bounded.** Challenge errors report `invalid_credential`,
  `too_many_attempts`, `account_locked`, `account_disabled`, `login_expired`, or
  `invalid_state`. They do not reveal whether an identifier exists.
- **Interactions expire.** Each interaction has its own lifetime; an expired
  interaction cannot be revived by resubmitting a form.

## Credential stages

| Method | Requirements and behaviour |
| --- | --- |
| Password | 12–1024 characters, checked against the configured policy and breach check. Five failed attempts lock the account; an administrator unlock is required when the lock is permanent. |
| Passkey | WebAuthn registration and assertion; the relying party ID is the host of `app.login_domain` and the origin must match exactly, including the port. Challenges live five minutes, are consumed atomically, and are invalidated by a stage change, identity reset, or session revocation. Requires JavaScript. |
| Authenticator app (TOTP) | Time-based one-time code. Enrollment starts and confirms inside the interaction, and the algorithm used for new enrollments can be changed afterwards from account security. |
| Recovery code | One-time code from the enrolled set. Reported as `urn:identity:amr:recovery-code` rather than as `otp`, so a recovery sign-in is distinguishable from a normal TOTP sign-in. |
| Client credentials | No user interaction. The client authenticates itself and receives only its own authority. |

Users may prefer passkeys, then an authenticator app; the preference changes
which method is offered first and never weakens a requirement. Management of
factors happens in the account center under security, not during an interactive
protocol flow.

## Assurance and freshness

Interactive sessions carry an authentication context class reference:

| ACR | Meaning |
| --- | --- |
| `aal1` | One factor completed |
| `aal2` | A second factor completed after the first |

`acr_satisfies` accepts an equal value, and `aal2` also satisfies a request for
`aal1`. A request for `aal2` from a password-only user becomes
`MfaEnrollmentRequired` rather than a silent downgrade. After login the chosen
level is written into the session and into the `acr` claim of issued tokens. Freshness is separate:
`max_age` is measured from the authentication event, and the window is measured
from the moment the stage completed, not from when the session was first created.
A forced reauthentication upgrades the bound session in place, so the user
keeps one session while the newer assurance and timestamp apply. For that bound
session the second-factor stage may be the only step requested, but a one-time
code never replaces the password stage for an interaction that is not already
bound to a session.

When the API needs a stronger level than the request currently presents,
[authorization.md](authorization.md#authentication-requirements) defines the
requirement and the step-up response. In the browser, reauthentication runs in a
popup and never replays the pending write.

## Sessions and account selection

- A session is created only for an interactive grant, and it is presented as an
  opaque browser cookie. The session identifier is separately protected and is
  not the same value as the authentication interaction.
- `prompt=select_account` asks the user to choose; without it, a valid session may
  be reused when the requested assurance and freshness still hold.
- Choosing an account records a selection source: `Auto` for a reused session,
  `AccountPicker` for an explicit choice, `FreshLogin` for a completed sign-in,
  and `Reauthentication` for a forced step-up. The last one never allows the
  interaction to drift to a different account.
- `login_hint` is accepted and carried through third-party initiated requests, but
  it does not by itself select a session or prove an identity.
- A user with several remembered accounts can sign out only the session named by
  a verified `id_token_hint`, never another remembered account.

## Consent

Consent is stored per client and user, not per token. A client authorization
carries one of three consent states:

| State | Effect on continue |
| --- | --- |
| `Approved` | Proceeds to code issuance |
| `Denied` | Ends the request with `access_denied` |
| `Pending` | Shows the consent page, unless the client is configured to skip consent and the request did not ask for it |

`prompt=consent` forces the page even for a client that normally skips it;
`prompt=none` cannot display it and returns `consent_required` instead. A
client-level setting may skip the page altogether, which records an approval
without asking; that is still not a permission grant, and the scopes remain the
intersection of what the client may request and what the user currently holds.

## Continue and code issuance

After the interaction reaches `Authenticated`, the browser is sent to
`/oauth2/continue`, which completes the stored request and returns the client to
its `redirect_uri` with an authorization code and the request `state`. The code
is single use, short lived, bound to the client and redirect URI, and records the
session that completed the interaction. Tokens issued from it carry that
session's `sid` claim.

At the token endpoint the authorization-code exchange rechecks the session before
issuing tokens. A revoked or expired session fails the exchange, and the code
cannot be redeemed twice.

## Refreshing tokens

- Refresh tokens rotate. A successfully redeemed refresh token is replaced, and
  the response carries the new one.
- Reuse detection matters: presenting an already-replaced refresh token revokes
  the whole token family and writes a `refresh_token.reuse_detected` audit event.
- Management scopes are never persisted as a refreshable grant; such a request is
  rejected rather than silently downgraded.
- A machine token is withdrawn through the client credential that issued it.

## Device authorization

Device clients use the RFC 8628 flow:

1. The client posts its client identifier and scopes to `POST /oauth2/device`.
2. The response carries a device code, a short user code, the verification URI,
   the expiry, and the polling interval.
3. The user opens the verification page at `/device` on Login, enters the user
   code, and is walked through the same sign-in and consent stages as a browser
   request.
4. The client polls `POST /oauth2/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`.

Details that matter for implementers:

- The device code is 256 bits and is stored only as a SHA-256 digest. The user
  code is eight characters drawn from a 20-character alphabet without ambiguous
  glyphs; the stored value is normalized for lookup, and a display form with a
  separator is returned to the user.
- The default request lifetime is 600 seconds and the default polling interval is
  five seconds; both are configurable within validated bounds. Polling too early
  adds five seconds to the advertised interval.
- Polling errors are `authorization_pending`, `slow_down`, `access_denied`, and
  `expired_token`.
- Redemption prepares the token set before touching persistence, then revalidates
  under a row lock and commits consumption together with the token records. A
  failed attempt leaves the code redeemable, and two concurrent polls cannot mint
  two token sets.

## Reauthentication for API calls

The Console and the account center call the GraphQL API with the user's session.
When a field requires stronger authentication than the session carries, the
server answers with an `insufficient_user_authentication` error that names the
required level. The client then starts a popup reauthentication instead of
guessing:

- The popup opens the authorization endpoint with the appropriate `acr_values`
  and `max_age`, reusing the session and identity hint where possible.
- The callback is validated for origin, `state`, window handle, and subject
  before the parent exchanges the code. A result from a stale or different
  session is rejected.
- The pending operation is not replayed. The client restores the user's draft and
  the user submits again, so a step-up cannot silently repeat a write.
- Explicit account switching uses `prompt=select_account`; ordinary sign-in omits
  `prompt`.

See [graphql.md](graphql.md#errors) for the error shape and
[security.md](security.md#authentication-browser-windows) for the browser-window
rules.

## Logout and session termination

- RP-initiated logout verifies `id_token_hint` when present, requires a
  `client_id` when a `post_logout_redirect_uri` is supplied, and accepts only a
  redirect URI registered for that client. `state` is appended to the redirect.
- Back-channel logout notifications are sent for clients configured with a
  back-channel URI; front-channel notifications are rendered as a page of
  iframes whose Content-Security-Policy admits only the registered origins.
- Ending a session makes pending code exchanges fail and stops that session's
  refresh tokens. Access tokens already issued remain valid until they expire,
  which is why the revocation endpoint exists for a specific token.
- Password changes revoke the user's other sessions, so they cannot refresh or
  finish a pending flow.

## Diagnostics

Every stage records structured events: sign-in attempts, lockouts, consent
decisions, code issuance, redemption failures, refresh reuse, logout, and
step-up rejections. Correlation identifiers travel in error details and
`x-request-id`, not in page furniture. See
[security.md](security.md#security-auditing) for what is audited and
[deploy/README.md](../deploy/README.md#observability) for where the telemetry
goes.

## Related pages

- [Protocol reference](protocol.md) — endpoints, client policy, PAR, resource indicators
- [Authorization model](authorization.md) — principals, scopes, effective permissions
- [GraphQL API](graphql.md) — bearer transport, `@access`, error envelope
- [Security](security.md) — password policy, MFA, sessions, auditing
- [Login guide](../apps/login/README.md) — routes, forms, passkeys, installer
