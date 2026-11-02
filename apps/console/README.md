# Console

Console is a static frontend. Business operations use the instance GraphQL API.

Installation stores issuer, login and console addresses independently in
`app.domain`, `app.login_domain` and `app.console_domain`. The server uses them
for first-party OAuth clients and allowed API origins. Local development uses
`public/config.json`. The production image obtains these addresses from Identity
at startup and writes `/run/identity-console/config.json`, served at `/config.json`
with `Cache-Control: no-store`.

## Container

Build from the repository root:

```sh
docker build -f deploy/docker/console.Dockerfile -t identity-console:local .
```

Configure a separate Console workload credential on Identity:

```yaml
internal:
  workloads:
    console:
      static_tokens:
        - file: /run/secrets/console-workload-token
```

Keep the existing `internal.workloads.login` authentication configured. Give
Console a different credential. Reusing one credential across workloads is
rejected. Kubernetes deployments may instead configure
`console.kubernetes_service_account` with `enabled: true` and an explicit
`audience`, `issuer`, `namespace`, and `service_account`, then mount a projected
token for that ServiceAccount into the Console container.

```sh
docker run --rm -p 8080:8080 \
  -e IDENTITY_INTERNAL_API_URL=https://identity:5151 \
  -e IDENTITY_WORKLOAD_TOKEN_FILE=/run/secrets/console-workload-token \
  -e IDENTITY_CA_FILE=/run/secrets/identity-ca.crt \
  --mount type=bind,source=/path/to/console-workload-token,target=/run/secrets/console-workload-token,readonly \
  --mount type=bind,source=/path/to/identity-ca.crt,target=/run/secrets/identity-ca.crt,readonly \
  identity-console:local
```

The entrypoint calls `GET /internal/workloads/self/runtime-configuration` using
the Console identity. Its response contains only browser-visible values; this
identity cannot access installation controls or Login client credentials. The
Console public client has no client secret. The workload credential is read only
by the entrypoint and is never written into the served configuration or static
assets. `IDENTITY_WORKLOAD_TOKEN` is also accepted when a mounted file is not used.

HTTPS and certificate verification are required for the internal fetch by
default. For a trusted private HTTP listener, explicitly set
`IDENTITY_INTERNAL_API_ALLOW_HTTP=true`. Startup retries transient failures for
a bounded period, validates the response, and atomically replaces the local
configuration before starting Nginx. Missing installation settings, rejected
credentials, or invalid responses stop startup. There is no development-config
or stale-file fallback. Restart the container after changing application domains.

The non-root runtime serves the SPA on HTTP port `8080`; terminate public HTTPS
at your ingress or reverse proxy using the installed `app.console_domain`.
Route the public issuer's `/graphql` path to Identity's GraphQL listener. Health
checks use the container-local `http://127.0.0.1:8081/health`. A read-only root
filesystem is supported with writable `/tmp` and `/run/identity-console` mounts.

The image workflow publishes `ghcr.io/<owner>/<repository>-console` for both
`linux/amd64` and `linux/arm64`, using the same release tag as Identity and Login.
Each platform image runs `tests/deployment/console-container.py` before the
multi-platform manifest is published.

## Authentication flows

Fresh authentication opens a centered browser popup, approximately 520 by 720
CSS pixels, while the workspace remains mounted. The callback is bound to the
current user, state, callback origin and popup window. Closing it preserves the
previous usable session. Success refreshes authorization data without replaying
a mutation. A blocked popup offers a user-triggered retry or full-page fallback.
Account switching uses a separate `prompt=select_account` flow.

No iframe is used for authentication. Development/preview deny page framing;
static hosts can apply `public/_headers`, or their equivalent HTTP header
configuration, to deny framing in production as well.
