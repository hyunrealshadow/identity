use crate::m20260306_031058_create_client::Client;
use sea_orm_migration::{async_trait, sea_orm};
use sea_orm_migration::{
    prelude::{
        DbErr, DeriveIden, DeriveMigrationName, Expr, ForeignKey, ForeignKeyAction, Index,
        MigrationTrait, SchemaManager, Table,
    },
    schema::{
        big_integer, boolean_null, integer_null, json_binary, json_binary_null, pk_auto,
        string_null, timestamp_with_time_zone, timestamp_with_time_zone_null,
    },
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
pub enum ClientOpenIdConnect {
    #[sea_orm(iden = "client_openid_connect")]
    Table,
    Id,
    ClientId,
    PostLogoutRedirectUris,
    FrontchannelLogoutUri,
    FrontchannelLogoutSessionRequired,
    BackchannelLogoutUri,
    BackchannelLogoutSessionRequired,
    ResponseTypes,
    GrantTypes,
    Contacts,
    LogoUri,
    ClientUri,
    PolicyUri,
    TosUri,
    SectorIdentifierUri,
    SubjectType,
    IdTokenSignedResponseAlgs,
    IdTokenEncryptedResponseAlgs,
    IdTokenEncryptedResponseEncs,
    UserinfoSignedResponseAlgs,
    UserinfoEncryptedResponseAlgs,
    UserinfoEncryptedResponseEncs,
    RequestObjectSigningAlgs,
    RequestObjectEncryptionAlgs,
    RequestObjectEncryptionEncs,
    TokenEndpointAuthMethods,
    TokenEndpointAuthSigningAlgs,
    DefaultMaxAge,
    RequireAuthTime,
    DefaultAcrValues,
    InitiateLoginUri,
    RequestUris,
    Settings,
    CreatedAt,
    UpdatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ClientOpenIdConnect::Table)
                    .if_not_exists()
                    .col(pk_auto(ClientOpenIdConnect::Id).big_integer())
                    .col(big_integer(ClientOpenIdConnect::ClientId))
                    .col(json_binary_null(
                        ClientOpenIdConnect::PostLogoutRedirectUris,
                    ))
                    .col(string_null(ClientOpenIdConnect::FrontchannelLogoutUri))
                    .col(boolean_null(
                        ClientOpenIdConnect::FrontchannelLogoutSessionRequired,
                    ))
                    .col(string_null(ClientOpenIdConnect::BackchannelLogoutUri))
                    .col(boolean_null(
                        ClientOpenIdConnect::BackchannelLogoutSessionRequired,
                    ))
                    .col(json_binary_null(ClientOpenIdConnect::ResponseTypes))
                    .col(json_binary_null(ClientOpenIdConnect::GrantTypes))
                    .col(json_binary_null(ClientOpenIdConnect::Contacts))
                    .col(string_null(ClientOpenIdConnect::LogoUri))
                    .col(string_null(ClientOpenIdConnect::ClientUri))
                    .col(string_null(ClientOpenIdConnect::PolicyUri))
                    .col(string_null(ClientOpenIdConnect::TosUri))
                    .col(string_null(ClientOpenIdConnect::SectorIdentifierUri))
                    .col(string_null(ClientOpenIdConnect::SubjectType))
                    .col(json_binary_null(
                        ClientOpenIdConnect::IdTokenSignedResponseAlgs,
                    ))
                    .col(json_binary_null(
                        ClientOpenIdConnect::IdTokenEncryptedResponseAlgs,
                    ))
                    .col(json_binary_null(
                        ClientOpenIdConnect::IdTokenEncryptedResponseEncs,
                    ))
                    .col(json_binary_null(
                        ClientOpenIdConnect::UserinfoSignedResponseAlgs,
                    ))
                    .col(json_binary_null(
                        ClientOpenIdConnect::UserinfoEncryptedResponseAlgs,
                    ))
                    .col(json_binary_null(
                        ClientOpenIdConnect::UserinfoEncryptedResponseEncs,
                    ))
                    .col(json_binary_null(
                        ClientOpenIdConnect::RequestObjectSigningAlgs,
                    ))
                    .col(json_binary_null(
                        ClientOpenIdConnect::RequestObjectEncryptionAlgs,
                    ))
                    .col(json_binary_null(
                        ClientOpenIdConnect::RequestObjectEncryptionEncs,
                    ))
                    .col(json_binary_null(
                        ClientOpenIdConnect::TokenEndpointAuthMethods,
                    ))
                    .col(json_binary_null(
                        ClientOpenIdConnect::TokenEndpointAuthSigningAlgs,
                    ))
                    .col(integer_null(ClientOpenIdConnect::DefaultMaxAge))
                    .col(boolean_null(ClientOpenIdConnect::RequireAuthTime))
                    .col(json_binary_null(ClientOpenIdConnect::DefaultAcrValues))
                    .col(string_null(ClientOpenIdConnect::InitiateLoginUri))
                    .col(json_binary_null(ClientOpenIdConnect::RequestUris))
                    .col(
                        json_binary(ClientOpenIdConnect::Settings)
                            .default(Expr::cust("'{}'::jsonb")),
                    )
                    .col(
                        timestamp_with_time_zone(ClientOpenIdConnect::CreatedAt)
                            .default(Expr::current_timestamp()),
                    )
                    .col(timestamp_with_time_zone_null(
                        ClientOpenIdConnect::UpdatedAt,
                    ))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_client_openid_connect_client_id")
                            .from(ClientOpenIdConnect::Table, ClientOpenIdConnect::ClientId)
                            .to(Client::Table, Client::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(ClientOpenIdConnect::Table)
                    .name("idx_client_openid_connect_client_id")
                    .col(ClientOpenIdConnect::ClientId)
                    .unique()
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .table(ClientOpenIdConnect::Table)
                    .name("idx_client_openid_connect_client_id")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(ClientOpenIdConnect::Table).to_owned())
            .await?;
        Ok(())
    }
}
