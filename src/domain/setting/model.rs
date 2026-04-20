use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use super::definition::{SettingDefinition, SettingValue};
pub use super::error::SettingValidationError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SettingOid(pub Uuid);

impl From<Uuid> for SettingOid {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<SettingOid> for Uuid {
    fn from(value: SettingOid) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingEntry<T> {
    pub oid: SettingOid,
    pub key: String,
    pub value: T,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::SettingOid;
    use uuid::Uuid;

    #[test]
    fn setting_oid_round_trips_through_uuid() {
        let raw = Uuid::new_v4();
        let oid = SettingOid::from(raw);

        assert_eq!(Uuid::from(oid), raw);
    }

    #[test]
    fn setting_oid_round_trips_through_json() {
        let oid = SettingOid::from(Uuid::new_v4());
        let json = serde_json::to_string(&oid).unwrap();
        let decoded: SettingOid = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, oid);
    }
}
