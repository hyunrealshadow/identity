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
use crate::{
    data_protection::{
        DATA_PROTECTION_KEY_SIZE, DataProtectionCipher, DataProtector, DataProtectorImpl,
    },
    openid_connect::provider::{OpenIdProviderService, SigningAlgorithmDetector},
    setting::runtime::SettingProvider,
};
use identity_domain::{
    auth::{
        LoginStatus,
        model::Login,
        repository::{LoginRepository, LoginRepositoryError},
    },
    client_authorization::{
        ClientAuthorization, ClientAuthorizationRepository, ClientAuthorizationRepositoryError,
        ClientAuthorizationType,
    },
    key::{
        CreateKeyJwkInput, KeyJwk, KeyJwkOid, KeyJwkRepository, KeyJwkRepositoryError,
        JwaSigningAlgorithm, Key, KeyData, KeyOid, KeyType,
        material::{SymmetricKeyAlgorithm, SymmetricKeyData},
        repository::{KeyRepository, KeyRepositoryError},
    },
    openid_connect::{
        OpenIdConnectClient, OpenIdConnectClientRepository, OpenIdConnectClientRepositoryError,
        OpenIdConnectCredential, OpenIdConnectCredentialData, OpenIdConnectCredentialRepository,
        OpenIdConnectCredentialRepositoryError, OpenIdConnectCredentialType,
    },
    setting::installation::{InstallationSetting, InstallationState},
    user::{
        User, UserOid,
        repository::{UserRepository, UserRepositoryError},
    },
};

mod fixtures;
mod flow;
mod request_object;
mod validation;
