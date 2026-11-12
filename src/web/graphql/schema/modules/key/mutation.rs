use async_graphql::{Context, Object, Result};
use identity_application::{
    authorization::ManagementTarget,
    key::management::{CreateSigningKeyCommand, KeyLifecycleCommand},
};
use identity_domain::authorization::ManagementScope;

use super::types::{
    CreateSigningKeyInput, KeyLifecycleInput, KeyPayload, RotateKeyPayload, decode_key_oid,
};
use crate::graphql::schema::{
    access::{AccessPolicy, access},
    authorization::request_context,
    error::app_error,
    management_guard::ManagementGuard,
    modules::resource::support::request_authority,
};

#[derive(Default)]
pub(crate) struct KeyMutation;

#[Object]
impl KeyMutation {
    /// Add a signing key with another algorithm. It becomes the newest active
    /// signing key; existing keys keep serving clients that ask for their
    /// algorithm.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::KeysCreate, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::KeysCreate))
    )]
    async fn create_signing_key(
        &self,
        ctx: &Context<'_>,
        input: CreateSigningKeyInput,
    ) -> Result<KeyPayload> {
        let request = request_context(ctx)?;
        let client_mutation_id = input.client_mutation_id.clone();
        let view = async {
            let authority = request_authority(request).await?;
            request
                .state
                .services()
                .key_management()
                .create_signing_key(
                    &authority,
                    CreateSigningKeyCommand {
                        algorithm: input.algorithm.into(),
                        key_algorithm: input.key_algorithm.map(Into::into),
                        client_mutation_id: input.client_mutation_id,
                    },
                )
                .await
        }
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(KeyPayload::new(view, client_mutation_id))
    }

    /// Replace a key in use with a new key of the same algorithm. The old key
    /// retires: it keeps verifying signatures or decrypting existing data
    /// until it expires.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::KeysRotate, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::KeysRotate))
    )]
    async fn rotate_key(
        &self,
        ctx: &Context<'_>,
        input: KeyLifecycleInput,
    ) -> Result<RotateKeyPayload> {
        replace(ctx, input, false).await
    }

    /// Rotate a key in use and revoke it at once. Tokens it signed stop
    /// validating and data it protected can no longer be read, so sessions and
    /// tokens it protected end. Requires both rotate and revoke permissions.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::KeysRotate, ManagementTarget::instance()).and(ManagementGuard::new(ManagementScope::KeysRevoke, ManagementTarget::instance()))",
        directive = access::apply(rotate_and_revoke_policy())
    )]
    async fn rotate_and_revoke_key(
        &self,
        ctx: &Context<'_>,
        input: KeyLifecycleInput,
    ) -> Result<RotateKeyPayload> {
        replace(ctx, input, true).await
    }

    /// Revoke a retired or expired key. A signing key leaves the published key
    /// set; data protected by an encryption key can no longer be read, which
    /// ends the sessions and tokens it protected.
    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::KeysRevoke, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::KeysRevoke))
    )]
    async fn revoke_key(&self, ctx: &Context<'_>, input: KeyLifecycleInput) -> Result<KeyPayload> {
        let key_oid = decode_key_oid(ctx, &input.id)?;
        let request = request_context(ctx)?;
        let client_mutation_id = input.client_mutation_id.clone();
        let view = async {
            let authority = request_authority(request).await?;
            request
                .state
                .services()
                .key_management()
                .revoke(
                    &authority,
                    KeyLifecycleCommand {
                        key_oid,
                        client_mutation_id: input.client_mutation_id,
                    },
                )
                .await
        }
        .await
        .map_err(|error| app_error(ctx, error))?;
        Ok(KeyPayload::new(view, client_mutation_id))
    }
}

async fn replace(
    ctx: &Context<'_>,
    input: KeyLifecycleInput,
    revoke_previous: bool,
) -> Result<RotateKeyPayload> {
    let key_oid = decode_key_oid(ctx, &input.id)?;
    let request = request_context(ctx)?;
    let client_mutation_id = input.client_mutation_id.clone();
    let (previous, successor) = async {
        let authority = request_authority(request).await?;
        let service = request.state.services().key_management();
        let command = KeyLifecycleCommand {
            key_oid,
            client_mutation_id: input.client_mutation_id,
        };
        if revoke_previous {
            service.rotate_and_revoke(&authority, command).await
        } else {
            service.rotate(&authority, command).await
        }
    }
    .await
    .map_err(|error| app_error(ctx, error))?;
    Ok(RotateKeyPayload::new(
        previous,
        successor,
        client_mutation_id,
    ))
}

/// Both requirements of `rotateAndRevokeKey`, published as one policy.
fn rotate_and_revoke_policy() -> AccessPolicy {
    let mut policy = ManagementGuard::policy(ManagementScope::KeysRotate);
    policy
        .scopes
        .push(ManagementScope::KeysRevoke.name().to_owned());
    policy
}
