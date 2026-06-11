extern crate self as domain;

pub mod auth;
pub mod client;
pub mod client_authorization;
pub mod data_protection;
pub mod key;
pub mod openid_connect;
pub mod setting;
pub mod user;

#[cfg(test)]
mod id_tests {
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        Hash,
        serde::Serialize,
        serde::Deserialize,
        derive_more::From,
        derive_more::Into,
    )]
    struct ExampleOid(pub uuid::Uuid);

    #[test]
    fn example_oid_round_trips_through_uuid() {
        let raw = uuid::Uuid::new_v4();
        let oid = ExampleOid::from(raw);

        assert_eq!(uuid::Uuid::from(oid), raw);
    }

    #[test]
    fn example_oid_round_trips_through_json() {
        let oid = ExampleOid::from(uuid::Uuid::new_v4());
        let json = serde_json::to_string(&oid).unwrap();
        let decoded: ExampleOid = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, oid);
    }
}
