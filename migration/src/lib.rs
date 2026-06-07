#![allow(elided_lifetimes_in_paths)]
use sea_orm_migration::async_trait;
use sea_orm_migration::prelude::MigrationTrait;
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
mod m20260428_000001_create_client_platform;

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
            Box::new(m20260426_000001_create_scope::Migration),
            Box::new(m20260426_000002_create_client_scope::Migration),
            Box::new(m20260427_000001_create_key_jwk::Migration),
            Box::new(m20260428_000001_create_client_platform::Migration),
        ]
    }
}
