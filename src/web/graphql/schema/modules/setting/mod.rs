//! Instance settings: read-only deployment facts plus the editable protocol
//! and authentication sections, each versioned and written as one unit.

mod mutation;
mod query;
mod types;

pub(crate) use mutation::SettingMutation;
pub(crate) use query::SettingQuery;
