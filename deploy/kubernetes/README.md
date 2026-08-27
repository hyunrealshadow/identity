# Raw manifests retired

The previous partial Login manifests have been replaced by the supported Helm
chart in [`../helm/identity`](../helm/identity). The chart keeps ServiceAccount
names, token audiences, Secrets, probes, Services, NetworkPolicies, and
multi-replica settings consistent in one values model.

[`k3s-gateway.example.yaml`](k3s-gateway.example.yaml) is a platform-level
example for enabling the packaged Traefik Gateway API provider and creating an
HTTPS Gateway. The application chart references that Gateway but does not own
it.
