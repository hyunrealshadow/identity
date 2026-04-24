use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::Utc;
use josekit::{
    jws::{ES256, EdDSA, JwsHeader, RS256},
    jwt,
    jwt::JwtPayload,
};
use openssl::rsa::Rsa;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{AuthorizationCodeGrantParams, RefreshTokenGrantParams, TokenService, verify_pkce};
use crate::{
    application::{
        openid_connect::provider::OpenIdProviderService, setting::runtime::SettingProvider,
    },
    domain::{
        client::model::{Client, ClientOid, ClientProtocol},
        client_request::{
            AuthorizationCodeData, ClientRequest, ClientRequestRepository,
            ClientRequestRepositoryError, ClientRequestType,
        },
        key::generator::AsymmetricKeyGenerator,
        key::{
            Key, KeyData, KeyOid, KeyType, material::AsymmetricKeyData, repository::KeyRepository,
        },
        openid_connect::{
            OpenIdConnectClient, OpenIdConnectClientMetadata, OpenIdConnectClientRepository,
            OpenIdConnectClientRepositoryError, OpenIdConnectCredential,
            OpenIdConnectCredentialData, OpenIdConnectCredentialRepository,
            OpenIdConnectCredentialRepositoryError, OpenIdConnectCredentialType,
            model::claim::JwtClaimNames,
        },
        setting::installation::{InstallationSetting, InstallationState},
        user::{
            User, UserOid,
            repository::{UserRepository, UserRepositoryError},
        },
    },
    infrastructure::crypto::key::AsymmetricKeyGeneratorImpl,
};

mod auth;
mod exchange;
mod fixtures;
mod helpers;
