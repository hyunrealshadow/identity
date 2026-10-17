use crate::openid_connect::jose::{
    request_object_content_encryption_algorithms, request_object_encryption_algorithms,
};
use identity_domain::{
    auth::{ACR_AAL1, ACR_AAL2},
    key::{JwaEncryptionAlgorithm, JwaSigningAlgorithm, JweContentEncryption, JwsAlgorithm},
    openid_connect::{
        ApiScope, ClaimType, Display, GrantType, ResponseMode, ResponseType, SubjectType,
        TokenEndpointAuthMethod,
        model::claim::{JwtClaimNames, StandardScopes},
    },
};

#[derive(Debug, Clone)]
pub struct OpenIdProviderCapabilities {
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<ResponseType>,
    pub response_modes_supported: Vec<ResponseMode>,
    pub grant_types_supported: Vec<GrantType>,
    pub acr_values_supported: Vec<String>,
    pub subject_types_supported: Vec<SubjectType>,
    pub id_token_signing_alg_values_supported: Vec<JwsAlgorithm>,
    pub id_token_encryption_alg_values_supported: Vec<JwaEncryptionAlgorithm>,
    pub id_token_encryption_enc_values_supported: Vec<JweContentEncryption>,
    pub userinfo_signing_alg_values_supported: Vec<JwsAlgorithm>,
    pub userinfo_encryption_alg_values_supported: Vec<JwaEncryptionAlgorithm>,
    pub userinfo_encryption_enc_values_supported: Vec<JweContentEncryption>,
    pub request_object_signing_alg_values_supported: Vec<JwsAlgorithm>,
    pub request_object_encryption_alg_values_supported: Vec<JwaEncryptionAlgorithm>,
    pub request_object_encryption_enc_values_supported: Vec<JweContentEncryption>,
    pub token_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,
    pub token_endpoint_auth_signing_alg_values_supported: Vec<JwsAlgorithm>,
    pub display_values_supported: Vec<Display>,
    pub claim_types_supported: Vec<ClaimType>,
    pub claims_supported: Vec<String>,
    pub claims_locales_supported: Vec<String>,
    pub ui_locales_supported: Vec<String>,
    pub claims_parameter_supported: bool,
    pub request_parameter_supported: bool,
    pub request_uri_parameter_supported: bool,
    pub require_request_uri_registration: bool,
}

impl Default for OpenIdProviderCapabilities {
    fn default() -> Self {
        Self {
            scopes_supported: vec![
                StandardScopes::OPENID.to_owned(),
                StandardScopes::PROFILE.to_owned(),
                StandardScopes::EMAIL.to_owned(),
                StandardScopes::ADDRESS.to_owned(),
                StandardScopes::PHONE.to_owned(),
                StandardScopes::OFFLINE_ACCESS.to_owned(),
                ApiScope::ACCOUNT.to_owned(),
                ApiScope::ACCOUNT_UPDATE.to_owned(),
                ApiScope::ACCOUNT_READ.to_owned(),
                ApiScope::SESSION.to_owned(),
                ApiScope::SESSION_REVOKE.to_owned(),
                ApiScope::SESSION_READ.to_owned(),
                ApiScope::PASSWORD_CHANGE.to_owned(),
            ],
            response_types_supported: vec![
                ResponseType::Code,
                ResponseType::IdToken,
                ResponseType::TokenIdToken,
                ResponseType::CodeIdToken,
                ResponseType::CodeToken,
                ResponseType::CodeTokenIdToken,
            ],
            response_modes_supported: vec![
                ResponseMode::Query,
                ResponseMode::Fragment,
                ResponseMode::FormPost,
            ],
            grant_types_supported: vec![
                GrantType::AuthorizationCode,
                GrantType::Implicit,
                GrantType::RefreshToken,
                GrantType::ClientCredentials,
                GrantType::DeviceCode,
            ],
            acr_values_supported: vec![ACR_AAL1.to_owned(), ACR_AAL2.to_owned()],
            subject_types_supported: vec![SubjectType::Public, SubjectType::Pairwise],
            id_token_signing_alg_values_supported: vec![JwsAlgorithm::Asymmetric(
                JwaSigningAlgorithm::Es256,
            )],
            id_token_encryption_alg_values_supported: vec![
                JwaEncryptionAlgorithm::RsaOaep,
                JwaEncryptionAlgorithm::RsaOaep256,
                JwaEncryptionAlgorithm::EcdhEs,
                JwaEncryptionAlgorithm::EcdhEsA128Kw,
                JwaEncryptionAlgorithm::EcdhEsA256Kw,
            ],
            id_token_encryption_enc_values_supported: vec![
                JweContentEncryption::A128CbcHs256,
                JweContentEncryption::A256CbcHs512,
                JweContentEncryption::A128Gcm,
                JweContentEncryption::A256Gcm,
            ],
            userinfo_signing_alg_values_supported: vec![],
            userinfo_encryption_alg_values_supported: vec![
                JwaEncryptionAlgorithm::RsaOaep,
                JwaEncryptionAlgorithm::RsaOaep256,
                JwaEncryptionAlgorithm::EcdhEs,
                JwaEncryptionAlgorithm::EcdhEsA128Kw,
                JwaEncryptionAlgorithm::EcdhEsA256Kw,
            ],
            userinfo_encryption_enc_values_supported: vec![
                JweContentEncryption::A128CbcHs256,
                JweContentEncryption::A256CbcHs512,
                JweContentEncryption::A128Gcm,
                JweContentEncryption::A256Gcm,
            ],
            request_object_signing_alg_values_supported:
                supported_request_object_signing_algorithms(),
            request_object_encryption_alg_values_supported: request_object_encryption_algorithms()
                .into_iter()
                .map(|value| value.parse().expect("supported JWE algorithm"))
                .collect(),
            request_object_encryption_enc_values_supported:
                request_object_content_encryption_algorithms()
                    .into_iter()
                    .map(|value| value.parse().expect("supported JWE content encryption"))
                    .collect(),
            token_endpoint_auth_methods_supported: supported_token_endpoint_auth_methods(),
            token_endpoint_auth_signing_alg_values_supported:
                supported_token_endpoint_auth_signing_algorithms(),
            display_values_supported: vec![Display::Page],
            claim_types_supported: vec![ClaimType::Normal],
            claims_supported: vec![
                JwtClaimNames::SUB.to_owned(),
                JwtClaimNames::ISS.to_owned(),
                JwtClaimNames::AUTH_TIME.to_owned(),
                JwtClaimNames::ACR.to_owned(),
                JwtClaimNames::AMR.to_owned(),
                JwtClaimNames::NAME.to_owned(),
                JwtClaimNames::GIVEN_NAME.to_owned(),
                JwtClaimNames::FAMILY_NAME.to_owned(),
                JwtClaimNames::MIDDLE_NAME.to_owned(),
                JwtClaimNames::NICKNAME.to_owned(),
                JwtClaimNames::PROFILE.to_owned(),
                JwtClaimNames::PICTURE.to_owned(),
                JwtClaimNames::WEBSITE.to_owned(),
                JwtClaimNames::GENDER.to_owned(),
                JwtClaimNames::BIRTHDATE.to_owned(),
                JwtClaimNames::ZONEINFO.to_owned(),
                JwtClaimNames::LOCALE.to_owned(),
                JwtClaimNames::UPDATED_AT.to_owned(),
                JwtClaimNames::PREFERRED_USERNAME.to_owned(),
                JwtClaimNames::EMAIL.to_owned(),
                JwtClaimNames::EMAIL_VERIFIED.to_owned(),
                JwtClaimNames::PHONE_NUMBER.to_owned(),
                JwtClaimNames::PHONE_NUMBER_VERIFIED.to_owned(),
                JwtClaimNames::ADDRESS.to_owned(),
            ],
            claims_locales_supported: vec![],
            ui_locales_supported: vec![],
            claims_parameter_supported: true,
            request_parameter_supported: true,
            request_uri_parameter_supported: true,
            require_request_uri_registration: true,
        }
    }
}

fn supported_request_object_signing_algorithms() -> Vec<JwsAlgorithm> {
    let mut algorithms = vec![JwsAlgorithm::None];
    algorithms.extend(supported_asymmetric_jws_algorithms());
    algorithms
}

fn supported_token_endpoint_auth_signing_algorithms() -> Vec<JwsAlgorithm> {
    let mut algorithms = vec![
        JwsAlgorithm::Hs256,
        JwsAlgorithm::Hs384,
        JwsAlgorithm::Hs512,
    ];
    algorithms.extend(supported_asymmetric_jws_algorithms());
    algorithms
}

fn supported_token_endpoint_auth_methods() -> Vec<TokenEndpointAuthMethod> {
    vec![
        TokenEndpointAuthMethod::ClientSecretBasic,
        TokenEndpointAuthMethod::ClientSecretPost,
        TokenEndpointAuthMethod::ClientSecretJwt,
        TokenEndpointAuthMethod::PrivateKeyJwt,
        TokenEndpointAuthMethod::None,
    ]
}

fn supported_asymmetric_jws_algorithms() -> Vec<JwsAlgorithm> {
    JwaSigningAlgorithm::all()
        .iter()
        .copied()
        .map(JwsAlgorithm::Asymmetric)
        .collect()
}
