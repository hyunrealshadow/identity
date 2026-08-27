# Identity Helm chart

This chart deploys replicated Identity and Login workloads. PostgreSQL and all
Secrets are intentionally external to the chart so uninstalling a release
cannot remove identity data or deployment root credentials.

## Prerequisites

- Kubernetes 1.25 or newer
- Helm 3
- PostgreSQL reachable from the Identity Pods
- Identity and Login images pushed to a registry reachable by the cluster
- An Identity TLS certificate trusted by Login
- A Kubernetes ServiceAccount issuer with OIDC discovery and JWKS endpoints
  reachable by Identity over HTTPS
- Gateway API CRDs and a controller when `gatewayApi.enabled=true`

The Identity certificate must cover all names used by Login:

- the public host from `identity.publicUrl`;
- `<release>-identity`;
- `<release>-identity-internal`;
- the corresponding namespace-qualified service names if the resolver or TLS
  policy expands them.

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

The CA Secret contains only the issuer certificate chain, never the Identity
private key. It is mounted into Login through `NODE_EXTRA_CA_CERTS`.

## Values and installation

Create a private values file:

```yaml
identity:
  image:
    repository: registry.example.com/identity
    tag: 1.0.0
  publicUrl: https://identity.example.com
  workload:
    issuer: https://kubernetes.default.svc.cluster.local

login:
  image:
    repository: registry.example.com/identity-login
    tag: 1.0.0
  publicUrl: https://account.example.com

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
neither route. The Identity and Login route switches can also be disabled
independently.

Both Services advertise `appProtocol: https` because their Pods terminate TLS.
The Gateway controller must support HTTPS backends and trust the certificates
served by the Pods. With a controller that supports it, use Gateway API
`BackendTLSPolicy` and a same-namespace CA ConfigMap to express that trust. Do
not reuse `kube-root-ca.crt` for application TLS; it is reserved for Kubernetes
internal endpoints.

Validate and install:

```sh
helm lint deploy/helm/identity -f values.production.yaml
helm template identity deploy/helm/identity \
  --namespace identity -f values.production.yaml
helm upgrade --install identity deploy/helm/identity \
  --namespace identity -f values.production.yaml
```

## Kubernetes workload verification

The chart creates separate Identity and Login ServiceAccounts with
`automountServiceAccountToken: false`. Login receives only a short-lived token
with the workload audience. Identity receives a separate short-lived token
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
  `system:serviceaccount:<release namespace>:<Login ServiceAccount>`.

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
Login-to-Identity HTTPS.

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
ports reachable, restrict Identity's internal port to Login Pods in the same
namespace, and do not impose egress restrictions.

If your Gateway controller runs in a known namespace, tighten public ingress
rules for that namespace in a downstream policy rather than disabling the
chart policy.
