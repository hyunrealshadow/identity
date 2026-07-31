# Login client credentials

The TanStack Start application is a confidential OAuth client. Its client
secret is used only by the server-side BFF and is never sent to browser
JavaScript.

During interactive installation Identity creates a UUID client ID and a
256-bit secret and stores them in PostgreSQL as part of the installation
transaction. The install API returns the credentials exactly once to the
server-side BFF. The BFF writes that response atomically to its credential
store; it never forwards the secret to browser JavaScript.

## Docker Compose

Mount a named volume at `/var/lib/identity-login` and configure:

```yaml
services:
  login:
    environment:
      IDENTITY_CLIENT_CREDENTIALS_FILE: /var/lib/identity-login/client.json
    volumes:
      - identity_login_credentials:/var/lib/identity-login

volumes:
  identity_login_credentials:
```

The file is generated with mode `0600`. Back up this volume together with the
PostgreSQL volume. Recreating a container does not recreate the OAuth client.

See `docker-compose.credentials.yaml` for a reusable Compose fragment.

## Kubernetes

Do not grant the Login Pod permission to create or update Kubernetes Secrets.
For initial installation, run one Login replica with a PVC mounted at
`/var/lib/identity-login` and configure
`IDENTITY_CLIENT_CREDENTIALS_FILE=/var/lib/identity-login/client.json`.
The BFF receives the generated credentials from Identity and writes that file
to the PVC.

For multiple replicas, a trusted operator can copy the generated values from
the credential file into a Kubernetes Secret and then inject
`IDENTITY_CLIENT_ID`, `IDENTITY_CLIENT_SECRET`, and
`IDENTITY_PUBLIC_APP_URL` into every replica:

```sh
kubectl exec deploy/identity-login -- cat /var/lib/identity-login/client.json
kubectl create secret generic identity-login-client \
  --from-literal=client-id='<client_id from the file>' \
  --from-literal=client-secret='<client_secret from the file>'
```

This post-install conversion requires no secret-writing RBAC in the
application. The example PVC is in `kubernetes/login-client-pvc.yaml`. Apply
`kubernetes/login-client-env.yaml` only after creating the Secret from the
credentials returned by Identity.
