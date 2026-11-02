use async_graphql::{Context, InputObject, Result};
use identity_application::error::{AppError, codes::rbac::RbacErrorCode};
use identity_domain::rbac::LocalizedMetadata;

use super::group::types::{LocalizedTextInput, LocalizedTextNode};
use crate::graphql::schema::error::app_error;

/// Optional translations. There is no default locale and the client chooses which
/// translation to present.
#[derive(Clone, InputObject)]
pub(crate) struct LocalizedMetadataInput {
    #[graphql(default, validator(max_items = 20))]
    pub names: Vec<LocalizedTextInput>,
    #[graphql(default, validator(max_items = 20))]
    pub descriptions: Vec<LocalizedTextInput>,
}

impl LocalizedMetadataInput {
    pub(crate) fn into_domain(self, ctx: &Context<'_>) -> Result<LocalizedMetadata> {
        LocalizedMetadata::canonicalize(
            self.names.into_iter().map(Into::into).collect(),
            self.descriptions.into_iter().map(Into::into).collect(),
        )
        .map_err(|_| {
            app_error(
                ctx,
                AppError::from_code(RbacErrorCode::InvalidLocalizedMetadata),
            )
        })
    }
}

pub(crate) fn names(metadata: &LocalizedMetadata) -> Vec<LocalizedTextNode> {
    metadata.names.iter().cloned().map(Into::into).collect()
}

pub(crate) fn descriptions(metadata: &LocalizedMetadata) -> Vec<LocalizedTextNode> {
    metadata
        .descriptions
        .iter()
        .cloned()
        .map(Into::into)
        .collect()
}
