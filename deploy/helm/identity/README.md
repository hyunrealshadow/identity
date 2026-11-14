# Identity Helm chart

This chart deploys replicated Identity, Login and Console workloads. PostgreSQL and all
Secrets are intentionally external to the chart so uninstalling a release
cannot remove identity data or deployment root credentials.

## Prerequisites

- Kubernetes 1.25 or newer
- Helm 3
- PostgreSQL reachable from the Identity Pods
- Identity, Login and Console images pushed to a registry reachable by the cluster
- An Identity TLS certificate trusted by Login when
  `identity.tls.enabled=true`
- A Kubernetes ServiceAccount issuer with OIDC discovery and JWKS endpoints
  reachable by Identity over HTTPS
- Gateway API CRDs and a controller when `gatewayApi.enabled=true`

When Identity terminates TLS itself, its certificate must cover all names used
by Login:

- the public issuer host recorded during installation;
- `<release>-server`;
- `<release>-server-internal`;
- the corresponding namespace-qualified service names if the resolver or TLS
  policy expands them.

## Public application addresses and first installation

Do not configure application `publicUrl` values in Helm. The installer records
the public HTTPS issuer, Login and Console URLs in database settings. Workloads
load them through Identity; Gateway hostnames and TLS certificates remain
deployment configuration and do not update these settings automatically.

After deployment, visit Login's `/install`. Enter HTTPS origins without deployment
paths. For a single hostname use, for example:

- issuer: `https://identity.example.com`
- Login: `https://identity.example.com`
- Console: `https://identity.example.com`

The three installer fields are editable. The suggested same-host addresses are
form defaults, not a restriction. Set routing hostnames first, then enter the
matching public addresses in the installer:

| Deployment | Issuer | Login | Console |
| --- | --- | --- | --- |
| Shared hostname | `https://identity.example.com` | `https://identity.example.com` | `https://identity.example.com` |
| Separate hostnames | `https://id.example.com` | `https://account.example.com` | `https://admin.example.com` |

Identity automatically appends `/console` to the Console origin and persists the
complete base URL. Do not enter `/console` in the installation field. Both
`https://admin.example.com` and its root-slash form `https://admin.example.com/`
are accepted; credentials, non-root paths, queries and fragments are rejected.

For a shared hostname, use:

```yaml
gatewayApi:
  enabled: true
  identity:
    hostnames: [identity.example.com]
  login:
    hostnames: [identity.example.com]
  console:
    hostnames: [] # Inherit Login hostnames.
```

For three separate hostnames, use:

```yaml
gatewayApi:
  enabled: true
  identity:
    hostnames: [id.example.com]
  login:
    hostnames: [account.example.com]
  console:
    hostnames: [admin.example.com]
```

Console also uses `/console` on its own hostname. To share only Login and
Console, keep the separate Identity hostname and leave Console hostnames empty.
Point the selected DNS names to the Gateway and configure its HTTPS listener
and certificates to accept those names. Visit `/install` on the Login hostname.
With externally managed routes, disable `gatewayApi.enabled` and forward the
same paths and hosts using the platform's existing proxy configuration.

Login is ready to serve installation before any runtime client exists. Console
waits for the installed configuration and remains unready until it can serve it.
Installation creates both built-in clients transactionally, preserving Console
callback and logout paths. A rejected form can be corrected and resubmitted.
Restart Console Pods after changing `IDENTITY_INTERNAL_API_URL` or the internal
API Service, which the Pod reads from its environment. Saved public addresses
and Console routing do not require a restart: the container serves
`/console/config.json` from Identity on every request. Login refreshes its
in-memory snapshot on demand.

Console public addresses are not repeated in workload environment variables.
Its optional routing hostname is configured above. Like Login, Console supports
either HTTP behind the HTTPS Gateway or direct Pod TLS through `console.tls`.
The Service, named port and readiness scheme follow that switch. The listener
uses `console.service.port` (8080 by default; 8081 is reserved for local health).
It runs as non-root with a read-only root filesystem and writable `emptyDir`
volumes for `/tmp` and runtime config. Readiness checks `/health/ready` on the
application listener. Startup/liveness exec probes keep the installation waiter
alive before configuration exists and check the local health listener afterward. Its workload
identity can fetch only Console configuration, not Login secrets or installation.
Set `console.enabled=false` to omit the workload, identity, route and policy.

## Required Secrets

The examples below install release `identity` in namespace `identity`. Secret
values are examples only.

```sh
kubectl create namespace identity

kubectl -n identity create secret generic identity-database \
  --from-literal=url='postgres://identity:replace-me@postgres.example:5432/identity'

kubectl -n identity create secret generic identity-login-session \
  --from-literal=session-secret='replace-with-at-least-32-random-bytes'

kubectl -n identity create secret tls identity-tls \
  --cert=identity.crt --key=identity.key

kubectl -n identity create secret generic identity-internal-ca \
  --from-file=ca.crt=identity-ca.crt
```

The two Identity TLS-related Secrets above are needed only when
`identity.tls.enabled=true`. The CA Secret contains only the issuer certificate
chain, never the Identity private key. It is mounted into Login through
`NODE_EXTRA_CA_CERTS`.

When `login.tls.enabled=true`, also create the configured Login TLS Secret:

```sh
kubectl -n identity create secret tls identity-login-tls \
  --cert=login.crt --key=login.key
```

For direct Console TLS, create a Secret containing its serving certificate and
key, then use the same TLS fields as Login:

```sh
kubectl -n identity create secret tls identity-console-tls \
  --cert=console.crt --key=console.key
```

```yaml
console:
  tls:
    enabled: true
    existingSecret: identity-console-tls
    certKey: tls.crt
    privateKeyKey: tls.key
```

These keys are mounted read-only at `/etc/identity/console-tls/tls.crt` and
`tls.key`. They identify Console to its clients. `console.internalCa` instead
verifies Identity's internal API and is mounted only when `identity.tls.enabled`
is true. These trust directions and Secrets are independent.

## Values and installation

Create a private values file:

```yaml
identity:
  image:
    repository: registry.example.com/identity
    tag: 1.0.0
  tls:
    enabled: false
    trustedProxies:
      - 10.42.0.0/16
    directHttpClients:
      - 10.42.0.0/16
  workload:
    issuer: https://kubernetes.default.svc.cluster.local

login:
  image:
    repository: registry.example.com/identity-login
    tag: 1.0.0
  tls:
    enabled: false

console:
  enabled: true
  image:
    repository: registry.example.com/identity-console
    tag: 1.0.0

gatewayApi:
  enabled: true
  parentRef:
    name: identity
    namespace: ""
    sectionName: https
  identity:
    enabled: true
    hostnames:
      - identity.example.com
  login:
    enabled: true
    hostnames:
      - account.example.com
```

The chart creates only application `HTTPRoute` resources. It deliberately does
not create a cluster-level `Gateway` or `GatewayClass`; those own listener
addresses and public TLS certificates and should normally be shared or managed
by the platform operator. Set `gatewayApi.enabled=false` (the default) to create
no routes. Identity, Login and Console route switches can also be disabled
independently. Console defaults to Login hostnames and matches `/console` with
no rewrite; `gatewayApi.console.hostnames` may explicitly select another
existing hostname. The image always serves `/console`. When Identity and Login
share a hostname, protocol paths (`/oauth2`, `/openid`, `/.well-known`, `/api/auth`, `/static`)
and `/graphql` go to Identity; `/console` goes to Console; the remaining paths
go to Login. The internal workload listener is never exposed by these routes.

`identity.tls.enabled`, `login.tls.enabled`, and `console.tls.enabled`
independently control whether each Pod terminates TLS. Their Services, named ports, and probes advertise and
use the matching `http` or `https` protocol. When a value is `true`, the
Gateway controller must support HTTPS backends and trust the certificate served
by that Pod. With a controller that supports it, use Gateway API
`BackendTLSPolicy` and a same-namespace CA ConfigMap to express that trust. Do
not reuse `kube-root-ca.crt` for application TLS; it is reserved for Kubernetes
internal endpoints.

Identity always exposes four private Service ports: public protocol API
(`5150`), internal workload API (`5151`), GraphQL (`5152`), and health
(`8081`). Login uses those ClusterIP Service endpoints in both TLS modes. Only
browser redirects use the installed issuer setting; Login never hairpins through
the Gateway or public DNS name. Console obtains its public configuration through
the authenticated internal Service using a separate projected ServiceAccount token.

When TLS is disabled, the public URL still must be HTTPS and the application
accepts public traffic only when the upstream proxy reports
`X-Forwarded-Proto: https` or `Forwarded: proto=https`. Identity additionally
requires the direct peer to belong to `identity.tls.trustedProxies`. Private
Login calls over HTTP are allowed only from
`identity.tls.directHttpClients`. At least one of those lists must be non-empty
when Identity TLS is disabled. Login validates the forwarding metadata,
so restrict its ingress to the Gateway or reverse-proxy Pods with a downstream
NetworkPolicy. Never expose either plain-HTTP Service directly outside the
cluster.

All Login-to-Identity backchannel URLs automatically follow
`identity.tls.enabled`. The internal workload API still requires its bearer
token in HTTP mode. Use encrypted CNI traffic, a service mesh, or keep Identity
TLS enabled when the cluster network is not trusted.

The chart writes Identity's JSON logs to the container console by default.
Identity and Login OTLP export are disabled until their respective
`observability.otlp.enabled` flags and collector endpoints are set. Enabling
either exporter without an endpoint fails template rendering.

Validate and install:

```sh
helm lint deploy/helm/identity -f values.production.yaml
helm template identity deploy/helm/identity \
  --namespace identity -f values.production.yaml
helm upgrade --install identity deploy/helm/identity \
  --namespace identity -f values.production.yaml
```

## Kubernetes workload verification

The chart creates separate Identity, Login and Console ServiceAccounts with
`automountServiceAccountToken: false`. Login and Console each receive a short-lived
token with the workload audience and their own subject. Identity receives a separate short-lived token
whose audience is the Kubernetes issuer, used only to authenticate issuer
discovery and JWKS requests. No custom Role or RoleBinding is needed: the
default `system:service-account-issuer-discovery` binding grants ServiceAccounts
access to those two non-resource endpoints.

Identity verifies the JWT signature using the configured issuer's OIDC
discovery and JWKS documents, then requires all of the following:

- the configured issuer;
- the configured audience;
- an unexpired token;
- the exact subject
  `system:serviceaccount:<release namespace>:<Login or Console ServiceAccount>`,
  bound to that workload's allowed operations.

Set `identity.workload.issuer` to the exact `iss` claim emitted by the cluster;
managed Kubernetes issuers commonly differ from the chart default.

For k3s, the default issuer is served by the Kubernetes API server with a
cluster-private certificate. The chart therefore defaults
`identity.workload.issuerCa` to the namespace-local `kube-root-ca.crt` ConfigMap
and mounts only its `ca.crt` bundle into Identity. Identity adds those roots to
the issuer discovery/JWKS HTTP client while retaining the normal system roots.
Because k3s disables anonymous API access, the chart also projects a distinct
token for the Identity ServiceAccount. Identity reloads this rotating token and
attaches it only to URLs with the issuer's exact origin, preventing a discovery
document from forwarding the credential to an external JWKS host. Disable
`identity.workload.issuerToken.enabled` only when the issuer endpoints accept
unauthenticated requests.

Disable `identity.workload.issuerCa.enabled` when the configured issuer uses
only publicly trusted roots, or point `configMapName` and `key` at another CA
bundle. The CA bundle is loaded when Identity starts; restart the Identity
Deployment after rotating that ConfigMap.

The Kubernetes root CA is intentionally scoped to issuer verification. The
`login.internalCa` Secret remains the separate trust anchor for
Login-to-Identity HTTPS and is mounted only when `identity.tls.enabled=true`.

## k3s Gateway API

Current k3s releases package Traefik's Gateway API CRDs, but the provider is
optional. Apply the example before enabling the chart routes:

```sh
kubectl create namespace identity
kubectl apply -f deploy/kubernetes/k3s-gateway.example.yaml
kubectl wait --for=condition=Accepted gatewayclass/traefik --timeout=120s
kubectl -n identity wait --for=condition=Programmed gateway/identity --timeout=120s
```

Create `identity-public-tls` and `identity-login-public-tls` in the `identity`
namespace before the Gateway can program its HTTPS listener. If you keep the
Gateway in another namespace, set `gatewayApi.parentRef.namespace` accordingly
and configure the listener's `allowedRoutes`; cross-namespace certificate
references may additionally require a `ReferenceGrant`.

The example uses only the standard-channel `HTTPRoute`, so Traefik's
`experimentalChannel` option is not needed. On older k3s builds, verify that the
Gateway API CRDs are present before installing the chart:

```sh
kubectl api-resources --api-group=gateway.networking.k8s.io
```

## Availability and network policy

The default two replicas and PodDisruptionBudgets allow one voluntary
disruption per component. Login readiness includes availability of a usable
built-in OAuth credential. The chart NetworkPolicies leave public and health
ports reachable, restrict Identity's internal port to Login Pods (and to Console
Pods while `console.enabled` is true) in the same namespace, and do not impose
egress restrictions.

If your Gateway controller runs in a known namespace, tighten public ingress
rules for that namespace in a downstream policy rather than disabling the
chart policy.
