use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

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

use super::{AuthorizationRequestParams, AuthorizeService};
use crate::application::{
    data_protection::{DataProtector, DataProtectorImpl},
    openid_connect::provider::OpenIdProviderService,
    setting::runtime::SettingProvider,
};
use crate::domain::{
    auth::{
        LoginStatus,
        model::Login,
        repository::{LoginRepository, LoginRepositoryError},
    },
    client::model::{Client, ClientProtocol},
    client_authorization::{
        ClientAuthorization, ClientAuthorizationRepository, ClientAuthorizationRepositoryError,
        ClientAuthorizationType,
    },
    key::{
        Key, KeyData, KeyOid, KeyType,
        material::{SymmetricKeyAlgorithm, SymmetricKeyData},
        repository::{KeyRepository, KeyRepositoryError},
    },
    openid_connect::{
        OpenIdConnectClient, OpenIdConnectClientMetadata, OpenIdConnectClientRepository,
        OpenIdConnectClientRepositoryError, OpenIdConnectCredential, OpenIdConnectCredentialData,
        OpenIdConnectCredentialRepository, OpenIdConnectCredentialRepositoryError,
        OpenIdConnectCredentialType,
    },
    setting::installation::{InstallationSetting, InstallationState},
};

mod fixtures;
mod flow;
mod request_object;
mod validation;
