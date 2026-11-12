//! Instance key management: metadata of signing and data encryption keys and
//! their rotation and revocation. Key material never crosses this surface.

mod mutation;
mod query;
mod types;

pub(crate) use mutation::KeyMutation;
pub(crate) use query::KeyQuery;
