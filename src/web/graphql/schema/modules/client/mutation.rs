use crate::graphql::schema::access::access;
use async_graphql::{Context, Object, Result};
use identity_application::{
    authorization::ManagementTarget,
    client::{
        AddClientJwksUriCommand, AddClientPublicKeyCommand, ClientStateCommand,
        CreateClientCommand, CreateClientSecretCommand, RevokeClientCredentialCommand,
        UpdateClientCommand,
    },
};
use identity_domain::authorization::ManagementScope;

use super::{
    integration,
    types::{
        AddClientJwksUriInput, AddClientPublicKeyInput, ClientCredentialPayload, ClientPayload,
        ClientSecretPayload, ClientStateInput, CreateClientInput, CreateClientSecretInput,
        DeleteClientPayload, RevokeClientCredentialInput, RotateClientSecretInput,
        UpdateClientInput, decode_client_oid, decode_credential_oid,
    },
};
use crate::graphql::schema::{
    authorization::request_context, error::app_error, management_guard::ManagementGuard,
};

#[derive(Default)]
pub(crate) struct ClientMutation;

#[Object]
impl ClientMutation {
    /// Create a client. Issue a secret separately with `createClientSecret`.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientsCreate, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientsCreate))
    )]
    async fn create_client(
        &self,
        ctx: &Context<'_>,
        input: CreateClientInput,
    ) -> Result<ClientPayload> {
        let client_mutation_id = input.client_mutation_id.clone();
        let record = integration::create_client(
            request_context(ctx)?,
            CreateClientCommand {
                name: input.name,
                description: input.description,
                names: input.names.into_iter().map(Into::into).collect(),
                descriptions: input.descriptions.into_iter().map(Into::into).collect(),
                settings: input.settings.into(),
                reason: input.reason,
                client_mutation_id: input.client_mutation_id,
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(ClientPayload::new(record, client_mutation_id))
    }

    /// Update display text and/or protocol settings. Changing what the client
    /// may obtain permanently withdraws what it was already issued.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientsUpdate, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientsUpdate))
    )]
    async fn update_client(
        &self,
        ctx: &Context<'_>,
        input: UpdateClientInput,
    ) -> Result<ClientPayload> {
        let client_oid = decode_client_oid(ctx, &input.id)?;
        let client_mutation_id = input.client_mutation_id.clone();
        let record = integration::update_client(
            request_context(ctx)?,
            UpdateClientCommand {
                client_oid,
                expected_version: input.expected_version,
                name: input.name,
                description: input.description,
                names: input
                    .names
                    .map(|names| names.into_iter().map(Into::into).collect()),
                descriptions: input
                    .descriptions
                    .map(|descriptions| descriptions.into_iter().map(Into::into).collect()),
                settings: input.settings.map(Into::into),
                reason: input.reason,
                client_mutation_id: input.client_mutation_id,
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(ClientPayload::new(record, client_mutation_id))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientsState, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientsState))
    )]
    async fn enable_client(
        &self,
        ctx: &Context<'_>,
        input: ClientStateInput,
    ) -> Result<ClientPayload> {
        set_enabled(ctx, input, true).await
    }

    /// Disabling rejects the client at every protocol endpoint and permanently
    /// withdraws what it was issued; enabling again does not restore them.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientsState, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientsState))
    )]
    async fn disable_client(
        &self,
        ctx: &Context<'_>,
        input: ClientStateInput,
    ) -> Result<ClientPayload> {
        set_enabled(ctx, input, false).await
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientsDelete, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientsDelete))
    )]
    async fn delete_client(
        &self,
        ctx: &Context<'_>,
        input: ClientStateInput,
    ) -> Result<DeleteClientPayload> {
        let client_mutation_id = input.client_mutation_id.clone();
        let command = state_command(ctx, input)?;
        let client_oid = integration::delete_client(request_context(ctx)?, command)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(DeleteClientPayload {
            client_oid,
            client_mutation_id,
        })
    }

    /// Issue an additional secret; existing secrets stay valid.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientCredentialsCreate, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientCredentialsCreate))
    )]
    async fn create_client_secret(
        &self,
        ctx: &Context<'_>,
        input: CreateClientSecretInput,
    ) -> Result<ClientSecretPayload> {
        let client_oid = decode_client_oid(ctx, &input.client_id)?;
        issue_secret(
            ctx,
            CreateClientSecretCommand {
                client_oid,
                expected_version: input.expected_version,
                replaces: None,
                lifetime_days: input.lifetime_days,
                reason: input.reason,
                client_mutation_id: input.client_mutation_id,
            },
        )
        .await
    }

    /// Issue a new secret and revoke the given one, which permanently withdraws
    /// what the client was already issued.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientCredentialsRotate, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientCredentialsRotate))
    )]
    async fn rotate_client_secret(
        &self,
        ctx: &Context<'_>,
        input: RotateClientSecretInput,
    ) -> Result<ClientSecretPayload> {
        let client_oid = decode_client_oid(ctx, &input.client_id)?;
        let credential_oid = decode_credential_oid(ctx, &input.credential_id)?;
        issue_secret(
            ctx,
            CreateClientSecretCommand {
                client_oid,
                expected_version: input.expected_version,
                replaces: Some(credential_oid),
                lifetime_days: input.lifetime_days,
                reason: input.reason,
                client_mutation_id: input.client_mutation_id,
            },
        )
        .await
    }

    /// Register a public key the client signs `private_key_jwt` assertions
    /// with. Existing credentials stay valid.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientCredentialsCreate, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientCredentialsCreate))
    )]
    async fn add_client_public_key(
        &self,
        ctx: &Context<'_>,
        input: AddClientPublicKeyInput,
    ) -> Result<ClientCredentialPayload> {
        let client_oid = decode_client_oid(ctx, &input.client_id)?;
        let client_mutation_id = input.client_mutation_id.clone();
        let result = integration::add_client_public_key(
            request_context(ctx)?,
            AddClientPublicKeyCommand {
                client_oid,
                expected_version: input.expected_version,
                key: input.key,
                expires_at: input.expires_at,
                reason: input.reason,
                client_mutation_id: input.client_mutation_id,
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(ClientCredentialPayload {
            client_oid,
            version: result.client.version,
            credential: result.credential,
            client_mutation_id,
        })
    }

    /// Register a JWKS URI the client publishes its signing keys at. The key
    /// set is fetched once to validate it and refreshed from the URI later.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientCredentialsCreate, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientCredentialsCreate))
    )]
    async fn add_client_jwks_uri(
        &self,
        ctx: &Context<'_>,
        input: AddClientJwksUriInput,
    ) -> Result<ClientCredentialPayload> {
        let client_oid = decode_client_oid(ctx, &input.client_id)?;
        let client_mutation_id = input.client_mutation_id.clone();
        let result = integration::add_client_jwks_uri(
            request_context(ctx)?,
            AddClientJwksUriCommand {
                client_oid,
                expected_version: input.expected_version,
                jwks_uri: input.jwks_uri,
                reason: input.reason,
                client_mutation_id: input.client_mutation_id,
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(ClientCredentialPayload {
            client_oid,
            version: result.client.version,
            credential: result.credential,
            client_mutation_id,
        })
    }

    /// Revoke a credential, permanently withdrawing what the client was issued.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientCredentialsRevoke, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientCredentialsRevoke))
    )]
    async fn revoke_client_credential(
        &self,
        ctx: &Context<'_>,
        input: RevokeClientCredentialInput,
    ) -> Result<ClientCredentialPayload> {
        let client_oid = decode_client_oid(ctx, &input.client_id)?;
        let credential_oid = decode_credential_oid(ctx, &input.credential_id)?;
        let client_mutation_id = input.client_mutation_id.clone();
        let result = integration::revoke_client_credential(
            request_context(ctx)?,
            RevokeClientCredentialCommand {
                client_oid,
                credential_oid,
                expected_version: input.expected_version,
                reason: input.reason,
                client_mutation_id: input.client_mutation_id,
            },
        )
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(ClientCredentialPayload {
            client_oid,
            version: result.client.version,
            credential: result.credential,
            client_mutation_id,
        })
    }
}

fn state_command(ctx: &Context<'_>, input: ClientStateInput) -> Result<ClientStateCommand> {
    Ok(ClientStateCommand {
        client_oid: decode_client_oid(ctx, &input.id)?,
        expected_version: input.expected_version,
        reason: input.reason,
        client_mutation_id: input.client_mutation_id,
    })
}

async fn set_enabled(
    ctx: &Context<'_>,
    input: ClientStateInput,
    enabled: bool,
) -> Result<ClientPayload> {
    let client_mutation_id = input.client_mutation_id.clone();
    let command = state_command(ctx, input)?;
    let record = integration::set_client_enabled(request_context(ctx)?, command, enabled)
        .await
        .map_err(|error| app_error(ctx, error))?;
    Ok(ClientPayload::new(record, client_mutation_id))
}

async fn issue_secret(
    ctx: &Context<'_>,
    command: CreateClientSecretCommand,
) -> Result<ClientSecretPayload> {
    let client_mutation_id = command.client_mutation_id.clone();
    let client_oid = command.client_oid;
    let result = integration::create_client_secret(request_context(ctx)?, command)
        .await
        .map_err(|error| app_error(ctx, error))?;
    Ok(ClientSecretPayload {
        client_oid,
        version: result.client.version,
        credential: result.secret.credential,
        secret: result.secret.secret,
        revoked: result.revoked,
        client_mutation_id,
    })
}
