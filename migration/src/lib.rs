#![allow(elided_lifetimes_in_paths)]
#![allow(clippy::wildcard_imports)]
pub use sea_orm_migration::prelude::*;
mod m20260305_071904_create_user;
mod m20260306_022501_create_user_credential;
mod m20260306_031058_create_client;
mod m20260306_090746_create_session;
mod m20260319_121151_create_key;
mod m20260328_132501_create_setting;
mod m20260407_060453_create_client_openid_connect;
mod m20260407_060506_create_client_openid_connect_credential;
mod m20260407_060938_create_client_request;
mod m20260407_071449_create_login;

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
            Box::new(m20260407_060938_create_client_request::Migration),
            Box::new(m20260407_071449_create_login::Migration),
        ]
    }
}
