use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use base64::Engine;
use chrono::Utc;
use josekit::{
    jws::{JwsHeader, RS256},
    jwt::{self, JwtPayload},
};
use openssl::rsa::Rsa;
use serde_json::json;
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    time::{Duration, timeout},
};
use url::Url;
use uuid::Uuid;

use super::{AuthorizationRequestParams, AuthorizeService, AuthorizeServiceDependencies};
use crate::{
    data_protection::{
        DATA_PROTECTION_KEY_SIZE, DataProtectionCipher, DataProtector, DataProtectorImpl,
    },
    openid_connect::provider::{OpenIdProviderService, SigningAlgorithmDetector},
    setting::runtime::SettingProvider,
};
use identity_domain::{
    auth::{SessionOid, repository::LoginRepository},
    client_authorization::{ClientAuthorization, ClientAuthorizationType},
    key::{
        JwaSigningAlgorithm, Key, KeyData, KeyJwk, KeyJwkOid, KeyOid, KeyType, PublicJwk,
        material::{SymmetricKeyAlgorithm, SymmetricKeyData},
    },
    openid_connect::{
        OpenIdConnectClient, OpenIdConnectClientRepository, OpenIdConnectClientRepositoryError,
        OpenIdConnectCredential, OpenIdConnectCredentialData, OpenIdConnectCredentialRepository,
        OpenIdConnectCredentialType,
    },
    setting::installation::{InstallationSetting, InstallationState},
    user::{User, UserOid},
};

mod fixtures;
mod flow;
mod interaction;
mod request_object;
mod third_party_initiated;
mod validation;
