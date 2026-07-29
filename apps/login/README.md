# Identity Login

TanStack Start application for interactive login and OAuth consent. The UI is
built with HeroUI v3 and Tailwind CSS v4.

## Development

```sh
pnpm dev
```

The Vite development server uses an automatically generated self-signed
certificate and is available at `https://localhost:3000`. Accept the
certificate warning in the browser the first time you open it. In development,
the Vite server also accepts the local Identity server's self-signed
certificate; production builds retain normal TLS certificate validation.

The Rust protocol service must be available to the Start server at
`IDENTITY_API_URL` (default `https://localhost:5150`). Login and consent APIs
are proxied server-side; their successful responses send the browser directly
back to the OP continuation endpoint. The Rust JSON API uses
`X-Sessions` and `X-CSRF-Token`; API responses return updated values through
the `sessions` and `csrf_token` JSON fields. The Start server keeps the session
list in its own secure, HttpOnly first-party cookie and translates it to the API
header.

Configure the Identity runtime settings to point to the development server:

- Login URL: `https://localhost:3000/login`
- Consent URL: `https://localhost:3000/consent`

When using a custom local hostname, start Vite with `--host`, trust its
self-signed certificate, and configure the same HTTPS origin in Identity.

All state-changing interactions are native HTML form POSTs. Client JavaScript
intercepts the same forms only to provide enhanced navigation; disabling
JavaScript preserves the complete login and consent flow.
