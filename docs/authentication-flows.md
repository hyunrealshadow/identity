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
| `IdentifierVerified` | User identified (or, while account existence is concealed, any identifier entered), first factor not yet accepted | Password, passkey, email code or link |
| `MfaRequired` | First factor accepted, a second factor is still required | OTP, recovery code, passkey |
| `MfaEnrollmentRequired` | The verified factors fall short of the requested class and the user has no credential that meets it | `aal2`: authenticator enrollment, then a completed session. `phr`: passkey registration, then a passkey challenge (an existing passkey may also be used) |
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
- **Enrollment keeps its own interaction.** Adding an authenticator app or a
  passkey withdraws credentials issued under the user's earlier credential set.
  When it is enrolled inside `MfaEnrollmentRequired`, the pending
  authorization or device request of that interaction is kept so the sign-in
  can complete; the user's other pending interactions and issued tokens are
  still withdrawn.
- **Failures are bounded.** Challenge errors report `invalid_credential`,
  `too_many_attempts`, `account_locked`, `account_disabled`, `login_expired`, or
  `invalid_state`. They do not reveal whether an identifier exists.
- **Interactions expire.** Each interaction has its own lifetime; an expired
  interaction cannot be revived by resubmitting a form.

### Concealing whether an account exists

The authentication setting `auth.login.identifier_enumeration_allowed`
(Console: *Reveal whether an account exists*) defaults to `true`, where an
unknown, locked, or disabled account is rejected at the identifier step. When it
is `false`:

- Every identifier reaches `IdentifierVerified` and continues to the password
  step. The interaction keeps the identifier as entered and shows only that, not
  the account's name or picture, and offers only the password (and email
  sign-in when it is on, for every identifier alike).
- A wrong password, an unknown account, and an account without a password all
  fail with the same error (code `11027`) after comparable
  hashing work. Reaching the lockout threshold is not reported either.
- A locked or disabled account is disclosed only after its correct password.
- Passkeys, authenticator codes, and recovery codes are refused before the
  password succeeds, so a passkey-only account cannot sign in from the
  identifier step. Selecting an existing browser session is unaffected.
- Identifier-stage rejections are still written to the audit log.
- Requesting a sign-in email answers the same whether or not anything is
  sent: the resend interval and send limit are kept on the interaction, the
  email is composed and sent in the background, and a code for an unknown
  account fails like a wrong one.

### Email sign-in

The authentication setting `auth.login.email_sign_in_enabled` (Console:
*Email sign-in*, default `false`) lets an account with a **verified** email
address use a one-time code or link sent to it instead of its password. It can
be turned on only while email delivery is configured, and is not offered while
delivery is off.

- It is a first factor: offered only at `IdentifierVerified`, never in
  `MfaRequired`. An account with an authenticator app or passkey still
  completes that second factor, and a request for `aal2` still enrolls one.
  The session records `urn:identity:amr:email` (RFC 8176 registers no email
  value), and a following second factor keeps it in place of `pwd`.
- One email carries a 6-digit code and a single-use link to
  `{login_domain}/login/email?login_id=…&token=…`. Both expire after 10 minutes
  and sending extends the interaction to at least that long. Opening the link
  only shows a confirmation; the sign-in happens when the user continues, so a
  mail scanner that fetches the link cannot use it.
- A resend replaces the previous code. Sends are at least 60 seconds apart and
  at most five per interaction; the code allows five wrong attempts per
  interaction, which also count towards the account lockout.
- The code is stored only data-protected and the link only as a SHA-256
  digest, in the interaction's authentication challenge, which the successful
  verification consumes.
- The message uses the template translation that matches the account's locale,
  then the request's `ui_locales`, then the Login page language (exact tag
  first, then the same language), and otherwise the template's default content.

## Credential stages

| Method | Requirements and behaviour |
| --- | --- |
| Password | 12–1024 characters, checked against the configured policy and breach check. Five failed attempts lock the account; an administrator unlock is required when the lock is permanent. |
| Passkey | WebAuthn registration and assertion; the relying party ID is the host of `app.login_domain` and the origin must match exactly, including the port. Challenges live five minutes, are consumed atomically, and are invalidated by a stage change, identity reset, or session revocation. Requires JavaScript. |
| Authenticator app (TOTP) | Time-based one-time code. Enrollment starts and confirms inside the interaction, and the algorithm used for new enrollments can be changed afterwards from account security. |
| Email code or link | First factor only, for a verified address while email sign-in is on; see [email sign-in](#email-sign-in). Works without JavaScript. |
| Recovery code | One-time code from the enrolled set. Reported as `urn:identity:amr:recovery-code` rather than as `otp`, so a recovery sign-in is distinguishable from a normal TOTP sign-in. |
| Client credentials | No user interaction. The client authenticates itself and receives only its own authority. |

Users may prefer passkeys, then an authenticator app; the preference changes
which method is offered first and never weakens a requirement. Management of
factors happens in the account center under security, not during an interactive
protocol flow.

## Assurance and freshness

Interactive sessions carry an authentication context class reference. The
classes are defined once, by `AuthenticationContextClass` in
`src/domain/auth/acr.rs` (mirrored for the frontends in
`packages/graphql-access/src/acr.ts`), and discovery advertises them in
`acr_values_supported`:

| ACR | Meaning | Established by |
| --- | --- | --- |
| `aal1` | One factor | Password |
| `aal2` | Two distinct factors | Password plus a one-time or recovery code, or a passkey |
| `phr` | Phishing resistant | A user-verified passkey |

`phr` is the OpenID EAP ACR Values name registered in the IANA LoA registry.
`aal1` and `aal2` are this instance's own values; federation profiles from that
registry are not used because they carry the federation's policy obligations.
`phrh` is not offered: a synced passkey cannot prove a hardware-bound key.

The classes are nested for the methods offered here: a passkey is
user-verified, so `phr` also satisfies `aal2`, and `aal2` satisfies `aal1`.
`acr_values` (and a client's `default_acr_values`, used when a request names
none) list the acceptable classes in order of preference; meeting any one of
them satisfies the request. Values this instance does not define are ignored,
and a list of only such values asks for nothing. An existing session and a new
login apply the same rule: a new login needs only the weakest class listed, so
`aal2 aal1` asks for no second factor, just as an existing `aal1` session
already satisfies it. The login keeps the whole ordered list
(`login.requested_acr_values`): the weakest class is its requirement and the
first is its preference. A request that prefers `phr` is offered an enrolled
passkey first, ahead of the user's own method order, without being required to
use one: `phr aal2` still accepts a one-time code. A request for `aal2` from a password-only user becomes
`MfaEnrollmentRequired` rather than a silent downgrade.

A `phr` request prefers a passkey. A one-time or recovery code still verifies a
second factor, after which the user registers a passkey on this device (with
recovery codes, when the account has none) and authenticates with it;
registration alone authenticates nothing. The bootstrap is only as phishing
resistant as the factors that authorized it.

The session stores the class actually established, and management admission
uses it. The `acr` claim reports the most preferred requested class the session
meets, so a client that checks the value against its own list recognizes it: a
passkey session answering `acr_values=aal2` reports `aal2`. Without a request the
established class is reported. Code exchange and refresh recompute the claim
from the live session and the original request. Freshness is separate:
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

When an existing session satisfies the request without any credential being
presented during the interaction, completing the request writes a
`session_reuse` audit record naming the user and the client in the same
transaction. A request in which the user did sign in already has its `sign_in`
or `session_reauthenticate` record, so it is not audited twice.

At the token endpoint the authorization-code exchange rechecks the session before
issuing tokens. A revoked or expired session fails the exchange, and the code
cannot be redeemed twice.

## Refreshing tokens

- Refresh tokens rotate. A successfully redeemed refresh token is replaced, and
  the response carries the new one.
- Reuse detection matters: presenting an already-replaced refresh token revokes
  the whole token family and writes a failed `token_replay` audit record.
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
- Revoking a refresh token ends its grant, including the access tokens issued
  from it, and writes a `token_revoke` audit record; revoking a single access
  token writes `access_token_revoke`. A client that revokes both at sign-out
  therefore leaves two records. Presenting an already revoked token again
  changes nothing and is not audited.
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
