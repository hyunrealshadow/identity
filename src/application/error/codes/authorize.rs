use crate::application::error::{code::AppErrorCode, kind::ErrorKind};

/// Error codes for `AuthorizeService` (OIDC authorization request processing).
/// Range: 6000–6099
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizeErrorCode {
    // --- client lookup ---
    /// `client_id` is not a valid UUID.
    ClientIdInvalid,
    /// OpenID Connect client not found.
    ClientNotFound,
    /// Database call to find client failed.
    ClientLookupFailed,

    // --- basic parameter validation ---
    /// `response_type` value could not be parsed.
    ResponseTypeInvalid,
    /// `redirect_uri` is not a valid URL.
    RedirectUriInvalid,
    /// `scope` value could not be parsed.
    ScopeInvalid,
    /// `openid` scope is required but absent.
    OpenidScopeRequired,
    /// `display` parameter value could not be parsed.
    DisplayValueInvalid,
    /// `prompt` parameter value could not be parsed.
    PromptValueInvalid,
    /// `max_age` parameter is not a valid integer.
    MaxAgeInvalid,
    /// `request_uri` parameter is not a valid URL.
    RequestUriInvalid,
    /// `code_challenge_method` value could not be parsed.
    CodeChallengeMethodInvalid,
    /// Both `request` and `request_uri` were provided simultaneously.
    RequestAndUriConflict,
    /// One or more required parameters are missing or blank.
    RequiredParamMissing,

    // --- redirect URI ---
    /// `redirect_uri` is not registered for the client.
    RedirectUriNotRegistered,

    // --- request_uri validation ---
    /// `request_uri` scheme is not `https`.
    RequestUriNotHttps,
    /// `request_uri` contains a fragment component.
    RequestUriHasFragment,
    /// `request_uri` targets a loopback or private-network host.
    RequestUriUnsafeHost,
    /// `request_uri` is not registered for the client.
    RequestUriNotRegistered,

    // --- request_uri fetching ---
    /// HTTP GET of `request_uri` failed.
    RequestUriFetchFailed,
    /// `request_uri` response returned a non-200 status.
    RequestUriNot200,
    /// `request_uri` response exceeded the maximum allowed size.
    RequestUriTooLarge,
    /// Failed to read or UTF-8 decode the `request_uri` response body.
    RequestUriReadFailed,

    // --- request object parsing ---
    /// Failed to decode the JWT header of the request object.
    RequestObjectHeaderInvalid,
    /// Failed to decode an unsigned (`alg=none`) request object.
    RequestObjectDecodeFailed,
    /// Request object signing algorithm is not supported.
    RequestObjectAlgUnsupported,

    // --- request object verification ---
    /// Database call to find client credential failed.
    CredentialLookupFailed,
    /// PEM public key stored for the client is invalid.
    RequestObjectKeyInvalid,
    /// Signature verification of the request object failed.
    RequestObjectVerifyFailed,

    // --- request object claims ---
    /// Request object `iss` claim does not match `client_id`.
    RequestObjectIssMismatch,
    /// Request object `aud` claim does not include the issuer.
    RequestObjectAudMismatch,
    /// Request object `exp` claim is in the past.
    RequestObjectExpired,
    /// Request object `nbf` claim is in the future.
    RequestObjectNotYetValid,
    /// Request object `iat` claim is in the future.
    RequestObjectIatFuture,
    /// A field in the request object does not match the corresponding outer parameter.
    RequestObjectFieldMismatch,
    /// A JSON field in the request object could not be parsed.
    RequestObjectJsonInvalid,

    // --- claims parameter ---
    /// `claims` parameter is not valid JSON.
    ClaimsParamInvalid,
    /// `claims` parameter is not a JSON object.
    ClaimsNotObject,
    /// `claims.id_token` or `claims.userinfo` is not a JSON object.
    ClaimsFieldNotObject,

    // --- request object payload decoding (unverified) ---
    /// Request object does not have a valid JWT segment structure.
    RequestObjectEncodingInvalid,
    /// Request object payload segment is not valid base64.
    RequestObjectBase64Invalid,
    /// Request object payload is not valid JSON.
    RequestObjectPayloadInvalid,

    // --- persistence ---
    /// Failed to serialize `AuthorizationRequestData`.
    SerializeRequestFailed,
    /// Database write of authorization request failed.
    StoreRequestFailed,
    /// Database write of pending login flow failed.
    StoreLoginFailed,

    // --- loading stored state ---
    /// Database read of client request record failed.
    LoadRequestFailed,
    /// Authorization request record was not found.
    AuthzRequestNotFound,
    /// Stored record type is not `AuthorizationRequest`.
    AuthzRequestTypeMismatch,
    /// Failed to deserialize stored `AuthorizationRequestData`.
    DeserializeRequestFailed,
    /// Stored `client_id` is not a valid UUID (data integrity error).
    StoredClientIdInvalid,
    /// Database read of login flow record failed.
    LoadLoginFailed,
    /// Login flow record was not found.
    LoginNotFound,
    /// Stored `redirect_uri` is not a valid URL (data integrity error).
    StoredRedirectUriInvalid,

    // --- code issuance ---
    /// Failed to serialize `AuthorizationCodeData`.
    SerializeCodeFailed,
    /// Database write of authorization code failed.
    StoreCodeFailed,

    // --- login_id ---
    /// Encrypted login_id decryption or parsing failed.
    LoginIdInvalid,
}

impl AppErrorCode for AuthorizeErrorCode {
    fn kind(self) -> ErrorKind {
        match self {
            Self::ClientIdInvalid => ErrorKind::Validation,
            Self::ClientNotFound => ErrorKind::Validation,
            Self::ClientLookupFailed => ErrorKind::Internal,
            Self::ResponseTypeInvalid => ErrorKind::Validation,
            Self::RedirectUriInvalid => ErrorKind::Validation,
            Self::ScopeInvalid => ErrorKind::Validation,
            Self::OpenidScopeRequired => ErrorKind::Validation,
            Self::DisplayValueInvalid => ErrorKind::Validation,
            Self::PromptValueInvalid => ErrorKind::Validation,
            Self::MaxAgeInvalid => ErrorKind::Validation,
            Self::RequestUriInvalid => ErrorKind::Validation,
            Self::CodeChallengeMethodInvalid => ErrorKind::Validation,
            Self::RequestAndUriConflict => ErrorKind::Validation,
            Self::RequiredParamMissing => ErrorKind::Validation,
            Self::RedirectUriNotRegistered => ErrorKind::Validation,
            Self::RequestUriNotHttps => ErrorKind::Validation,
            Self::RequestUriHasFragment => ErrorKind::Validation,
            Self::RequestUriUnsafeHost => ErrorKind::Validation,
            Self::RequestUriNotRegistered => ErrorKind::Validation,
            Self::RequestUriFetchFailed => ErrorKind::Validation,
            Self::RequestUriNot200 => ErrorKind::Validation,
            Self::RequestUriTooLarge => ErrorKind::Validation,
            Self::RequestUriReadFailed => ErrorKind::Validation,
            Self::RequestObjectHeaderInvalid => ErrorKind::Validation,
            Self::RequestObjectDecodeFailed => ErrorKind::Validation,
            Self::RequestObjectAlgUnsupported => ErrorKind::Validation,
            Self::CredentialLookupFailed => ErrorKind::Internal,
            Self::RequestObjectKeyInvalid => ErrorKind::Validation,
            Self::RequestObjectVerifyFailed => ErrorKind::Validation,
            Self::RequestObjectIssMismatch => ErrorKind::Validation,
            Self::RequestObjectAudMismatch => ErrorKind::Validation,
            Self::RequestObjectExpired => ErrorKind::Validation,
            Self::RequestObjectNotYetValid => ErrorKind::Validation,
            Self::RequestObjectIatFuture => ErrorKind::Validation,
            Self::RequestObjectFieldMismatch => ErrorKind::Validation,
            Self::RequestObjectJsonInvalid => ErrorKind::Validation,
            Self::ClaimsParamInvalid => ErrorKind::Validation,
            Self::ClaimsNotObject => ErrorKind::Validation,
            Self::ClaimsFieldNotObject => ErrorKind::Validation,
            Self::RequestObjectEncodingInvalid => ErrorKind::Validation,
            Self::RequestObjectBase64Invalid => ErrorKind::Validation,
            Self::RequestObjectPayloadInvalid => ErrorKind::Validation,
            Self::SerializeRequestFailed => ErrorKind::Internal,
            Self::StoreRequestFailed => ErrorKind::Internal,
            Self::StoreLoginFailed => ErrorKind::Internal,
            Self::LoadRequestFailed => ErrorKind::Internal,
            Self::AuthzRequestNotFound => ErrorKind::Validation,
            Self::AuthzRequestTypeMismatch => ErrorKind::Validation,
            Self::DeserializeRequestFailed => ErrorKind::Internal,
            Self::StoredClientIdInvalid => ErrorKind::Internal,
            Self::LoadLoginFailed => ErrorKind::Internal,
            Self::LoginNotFound => ErrorKind::Validation,
            Self::StoredRedirectUriInvalid => ErrorKind::Internal,
            Self::SerializeCodeFailed => ErrorKind::Internal,
            Self::StoreCodeFailed => ErrorKind::Internal,
            Self::LoginIdInvalid => ErrorKind::Validation,
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::ClientIdInvalid => 6000,
            Self::ClientNotFound => 6001,
            Self::ClientLookupFailed => 6002,
            Self::ResponseTypeInvalid => 6003,
            Self::RedirectUriInvalid => 6004,
            Self::ScopeInvalid => 6005,
            Self::OpenidScopeRequired => 6006,
            Self::DisplayValueInvalid => 6007,
            Self::PromptValueInvalid => 6008,
            Self::MaxAgeInvalid => 6009,
            Self::RequestUriInvalid => 6010,
            Self::CodeChallengeMethodInvalid => 6011,
            Self::RequestAndUriConflict => 6012,
            Self::RequiredParamMissing => 6013,
            Self::RedirectUriNotRegistered => 6014,
            Self::RequestUriNotHttps => 6015,
            Self::RequestUriHasFragment => 6016,
            Self::RequestUriUnsafeHost => 6017,
            Self::RequestUriNotRegistered => 6018,
            Self::RequestUriFetchFailed => 6019,
            Self::RequestUriNot200 => 6020,
            Self::RequestUriTooLarge => 6021,
            Self::RequestUriReadFailed => 6022,
            Self::RequestObjectHeaderInvalid => 6023,
            Self::RequestObjectDecodeFailed => 6024,
            Self::RequestObjectAlgUnsupported => 6025,
            Self::CredentialLookupFailed => 6026,
            Self::RequestObjectKeyInvalid => 6027,
            Self::RequestObjectVerifyFailed => 6028,
            Self::RequestObjectIssMismatch => 6029,
            Self::RequestObjectAudMismatch => 6030,
            Self::RequestObjectExpired => 6031,
            Self::RequestObjectNotYetValid => 6032,
            Self::RequestObjectIatFuture => 6033,
            Self::RequestObjectFieldMismatch => 6034,
            Self::RequestObjectJsonInvalid => 6035,
            Self::ClaimsParamInvalid => 6036,
            Self::ClaimsNotObject => 6037,
            Self::ClaimsFieldNotObject => 6038,
            Self::RequestObjectEncodingInvalid => 6039,
            Self::RequestObjectBase64Invalid => 6040,
            Self::RequestObjectPayloadInvalid => 6041,
            Self::SerializeRequestFailed => 6042,
            Self::StoreRequestFailed => 6043,
            Self::StoreLoginFailed => 6044,
            Self::LoadRequestFailed => 6045,
            Self::AuthzRequestNotFound => 6046,
            Self::AuthzRequestTypeMismatch => 6047,
            Self::DeserializeRequestFailed => 6048,
            Self::StoredClientIdInvalid => 6049,
            Self::LoadLoginFailed => 6050,
            Self::LoginNotFound => 6051,
            Self::StoredRedirectUriInvalid => 6052,
            Self::SerializeCodeFailed => 6053,
            Self::StoreCodeFailed => 6054,
            Self::LoginIdInvalid => 6055,
        }
    }
}
