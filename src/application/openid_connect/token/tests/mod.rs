use std::sync::Arc;

use async_trait::async_trait;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{Duration, Utc};
use identity_domain::{data_protection::KeyRing, key::JwsAlgorithm};
use josekit::{
    jwk::{
        Jwk, KeyPair,
        alg::{
            ec::{EcCurve, EcKeyPair},
            ed::{EdCurve, EdKeyPair},
            rsa::RsaKeyPair,
            rsapss::RsaPssKeyPair,
        },
    },
    jws::{
        ES256, ES256K, ES384, ES512, EdDSA, HS256, HS384, HS512, JwsHeader, PS256, PS384, PS512,
        RS256, RS384, RS512,
    },
    jwt,
    jwt::JwtPayload,
    util::{SHA_256, SHA_384, SHA_512},
};
use openssl::rsa::Rsa;
use sha2::{Digest, Sha256, Sha384, Sha512};
use uuid::Uuid;

use self::fixtures::{
    InMemoryClientRepository, InMemoryDataProtector, InMemoryUserRepository,
    MockClientAuthorizationRepository, ScopedClaimsClientRepository, cred_repo_with,
    jwk_repo_with_bindings, key_repo_with_keys, provider_service, signing_algorithm_detector,
};
use super::{
    AuthorizationCodeGrantParams, ClientCredentialsGrantParams, DeviceCodeGrantParams,
    RefreshTokenGrantParams, TokenService, TokenServiceDependencies, signing::SignIdTokenInput,
    verify_pkce,
};
use crate::{
    application::{
        error::AppError,
        key::asymmetric::{AsymmetricKeyService, GeneratedKeyJwk, KeyJwkGenerator},
        openid_connect::provider::{OpenIdProviderService, SigningAlgorithmDetector},
    },
    domain::{
        client::model::ClientOid,
        client_authorization::{
            AuthorizationCodeData, ClientAuthorizationData, ClientAuthorizationRepository,
            ClientAuthorizationType, RefreshTokenData,
        },
        key::{
            JwaSigningAlgorithm, Key, KeyData, KeyJwk, KeyJwkOid, KeyOid, KeyType, PublicJwk,
            generator::{AsymmetricKeyGenerator, AsymmetricKeySpec, KeyMaterialError},
            material::AsymmetricKeyData,
        },
        openid_connect::{
            OpenIdConnectClient, OpenIdConnectClientRepository, OpenIdConnectClientRepositoryError,
            OpenIdConnectCredential, OpenIdConnectCredentialData, OpenIdConnectCredentialType,
            model::claim::JwtClaimNames,
        },
        user::{
            User, UserOid,
            repository::{UserRepository, UserRepositoryError},
        },
    },
    key::runtime::{RuntimeKeyRing, RuntimeKeyRingProvider, RuntimeSigningKey},
    openid_connect::{
        tests::fixtures::{
            client::{test_client, test_metadata, test_platforms, test_scopes},
            mocks::{MockDeviceAuthorizationRepository, MockKeyJwkRepository, MockKeyRepository},
        },
        user_info::UserInfoService,
    },
    setting::{AppSettings, InstallationSettings},
};

use signing::*;

mod auth;
mod exchange;
mod fixtures;
mod helpers;
mod introspection;
mod revocation;

mod signing;
