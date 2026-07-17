# Identity Login

TanStack Start application for interactive login and OAuth consent. The UI is
built with HeroUI v3 and Tailwind CSS v4.

## Development

```sh
pnpm dev
```

The Rust protocol service must be available to the Start server at
`IDENTITY_API_URL` (default `https://127.0.0.1:5150`). Login, consent, and the
protocol continuation endpoint are proxied server-side. The Rust JSON API uses
`X-Sessions` and `X-CSRF-Token`; API responses return updated values through
the `sessions` and `csrf_token` JSON fields. The Start server keeps the session
list in its own secure, HttpOnly first-party cookie and translates it to the API
header.

Expose this application through a local TLS proxy and configure the Identity
runtime settings to point to its HTTPS origin, for example:

- Login URL: `https://login.localhost/login`
- Consent URL: `https://login.localhost/consent`

All state-changing interactions are native HTML form POSTs. Client JavaScript
intercepts the same forms only to provide enhanced navigation; disabling
JavaScript preserves the complete login and consent flow.
