# Console

Console is a static frontend. Business operations use the instance GraphQL API.

Installation stores issuer, login and console addresses independently in
`app.domain`, `app.login_domain` and `app.console_domain`. The server uses them
for first-party OAuth clients and allowed API origins. Configure
`public/config.json` with the same issuer, account and callback addresses.

Fresh authentication opens a centered browser popup, approximately 520 by 720
CSS pixels, while the workspace remains mounted. The callback is bound to the
current user, state, callback origin and popup window. Closing it preserves the
previous usable session. Success refreshes authorization data without replaying
a mutation. A blocked popup offers a user-triggered retry or full-page fallback.
Account switching uses a separate `prompt=select_account` flow.

No iframe is used for authentication. Development/preview deny page framing;
static hosts can apply `public/_headers`, or their equivalent HTTP header
configuration, to deny framing in production as well.
