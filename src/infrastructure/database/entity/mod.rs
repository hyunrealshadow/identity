//! Current persistence schema expressed as SeaORM entities.
//!
//! These definitions evolve with the current database schema; historical
//! structure remains encoded by the ordered migration crate.

pub mod prelude;

pub mod client;
pub mod client_authorization;
pub mod client_open_id_connect;
pub mod client_open_id_connect_credential;
pub mod client_platform;
pub mod client_scope;
pub mod key;
pub mod key_jwk;
pub mod login;
pub mod scope;
pub mod session;
pub mod setting;
pub mod user;
pub mod user_credential;

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, Schema, sea_query::PostgresQueryBuilder};

    use super::{client_authorization, login, session, user};

    #[test]
    fn entity_metadata_preserves_schema_defaults_and_indexes() {
        let schema = Schema::new(DatabaseBackend::Postgres);
        let user_table = schema
            .create_table_from_entity(user::Entity)
            .to_string(PostgresQueryBuilder);

        assert!(user_table.contains("gen_random_uuid()"));
        assert!(user_table.contains("DEFAULT FALSE"));
        assert!(user_table.contains("DEFAULT TRUE"));
        assert!(user_table.contains("\"preferences\" jsonb"));
        assert!(user_table.contains("'{}'::jsonb"));
        assert!(user_table.contains("CURRENT_TIMESTAMP"));

        assert_eq!(schema.create_index_from_entity(session::Entity).len(), 2);
        assert_eq!(schema.create_index_from_entity(login::Entity).len(), 5);
        assert_eq!(
            schema
                .create_index_from_entity(client_authorization::Entity)
                .len(),
            3
        );
    }
}
