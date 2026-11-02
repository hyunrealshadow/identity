#![allow(elided_lifetimes_in_paths)]
use sea_orm_migration::{async_trait, prelude::MigrationTrait};

pub use sea_orm_migration::prelude::{DbErr, MigratorTrait};
mod m20260305_071904_create_user;
mod m20260306_022501_create_user_credential;
mod m20260306_031058_create_client;
mod m20260306_090746_create_session;
mod m20260319_121151_create_key;
mod m20260328_132501_create_setting;
mod m20260407_060453_create_client_openid_connect;
mod m20260407_060506_create_client_openid_connect_credential;
mod m20260407_060938_create_client_authorization;
mod m20260407_071449_create_login;
mod m20260426_000001_create_scope;
mod m20260426_000002_create_client_scope;
mod m20260427_000001_create_key_jwk;
mod m20260428_000001_create_client_openid_connect_platform;
mod m20260907_000001_create_user_client_consent;
mod m20260927_000001_create_client_openid_connect_cors_origin;
mod m20261001_000001_create_resource;

mod m20261016_000001_create_authentication_challenge;
mod m20261017_000001_create_security_audit;
mod m20261022_000005_create_role;
mod m20261022_000006_create_role_permission;
mod m20261022_000007_create_user_role_binding;
mod m20261022_000012_create_user_group;
mod m20261022_000013_create_group_membership;
mod m20261022_000014_create_group_role_binding;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260305_071904_create_user::Migration),
            Box::new(m20260306_022501_create_user_credential::Migration),
            Box::new(m20260306_031058_create_client::Migration),
            Box::new(m20260306_090746_create_session::Migration),
            Box::new(m20260319_121151_create_key::Migration),
            Box::new(m20260328_132501_create_setting::Migration),
            Box::new(m20260407_060453_create_client_openid_connect::Migration),
            Box::new(m20260407_060506_create_client_openid_connect_credential::Migration),
            Box::new(m20260407_060938_create_client_authorization::Migration),
            Box::new(m20260407_071449_create_login::Migration),
            // Resource ownership must exist before scope foreign keys.
            Box::new(m20261001_000001_create_resource::Migration),
            Box::new(m20260426_000001_create_scope::Migration),
            Box::new(m20260426_000002_create_client_scope::Migration),
            Box::new(m20260427_000001_create_key_jwk::Migration),
            Box::new(m20260428_000001_create_client_openid_connect_platform::Migration),
            Box::new(m20260907_000001_create_user_client_consent::Migration),
            Box::new(m20260927_000001_create_client_openid_connect_cors_origin::Migration),
            Box::new(m20261016_000001_create_authentication_challenge::Migration),
            Box::new(m20261017_000001_create_security_audit::Migration),
            Box::new(m20261022_000005_create_role::Migration),
            Box::new(m20261022_000006_create_role_permission::Migration),
            Box::new(m20261022_000007_create_user_role_binding::Migration),
            Box::new(m20261022_000012_create_user_group::Migration),
            Box::new(m20261022_000013_create_group_membership::Migration),
            Box::new(m20261022_000014_create_group_role_binding::Migration),
        ]
    }
}
