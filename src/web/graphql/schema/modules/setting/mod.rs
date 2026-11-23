//! Instance settings: read-only deployment facts plus the editable protocol,
//! authentication and email sections, each versioned and written as one unit.

mod email;
mod mutation;
mod query;
mod types;

pub(crate) use mutation::SettingMutation;
pub(crate) use query::SettingQuery;
