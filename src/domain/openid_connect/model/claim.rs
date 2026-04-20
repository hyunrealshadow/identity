//! JWT Claim Names as defined by RFC 7519, OpenID Connect Core 1.0, RFC 8693, and RFC 9068.
//!
//! These constants follow the naming conventions from Microsoft's
//! IdentityModel library (JwtRegisteredClaimNames).

pub struct JwtClaimNames;

impl JwtClaimNames {
    // RFC 7519 Registered Claims
    pub const SUB: &'static str = "sub";
    pub const ISS: &'static str = "iss";
    pub const AUD: &'static str = "aud";
    pub const EXP: &'static str = "exp";
    pub const NBF: &'static str = "nbf";
    pub const IAT: &'static str = "iat";
    pub const JTI: &'static str = "jti";

    // OpenID Connect Core 1.0 Claims
    pub const NONCE: &'static str = "nonce";
    pub const AUTH_TIME: &'static str = "auth_time";
    pub const ACR: &'static str = "acr";
    pub const AMR: &'static str = "amr";
    pub const AZP: &'static str = "azp";
    pub const AT_HASH: &'static str = "at_hash";
    pub const C_HASH: &'static str = "c_hash";
    pub const SID: &'static str = "sid";

    // OpenID Connect Standard Claims
    pub const NAME: &'static str = "name";
    pub const GIVEN_NAME: &'static str = "given_name";
    pub const FAMILY_NAME: &'static str = "family_name";
    pub const MIDDLE_NAME: &'static str = "middle_name";
    pub const NICKNAME: &'static str = "nickname";
    pub const PREFERRED_USERNAME: &'static str = "preferred_username";
    pub const PROFILE: &'static str = "profile";
    pub const PICTURE: &'static str = "picture";
    pub const WEBSITE: &'static str = "website";
    pub const EMAIL: &'static str = "email";
    pub const EMAIL_VERIFIED: &'static str = "email_verified";
    pub const GENDER: &'static str = "gender";
    pub const BIRTHDATE: &'static str = "birthdate";
    pub const ZONEINFO: &'static str = "zoneinfo";
    pub const LOCALE: &'static str = "locale";
    pub const PHONE_NUMBER: &'static str = "phone_number";
    pub const PHONE_NUMBER_VERIFIED: &'static str = "phone_number_verified";
    pub const ADDRESS: &'static str = "address";
    pub const UPDATED_AT: &'static str = "updated_at";

    // RFC 8693 Token Exchange Claims
    pub const SCOPE: &'static str = "scope";
    pub const CLIENT_ID: &'static str = "client_id";
    pub const ACT: &'static str = "act";
    pub const MAY_ACT: &'static str = "may_act";

    // RFC 9068 / RFC 7643 Authorization Claims
    pub const ROLES: &'static str = "roles";
    pub const GROUPS: &'static str = "groups";
    pub const ENTITLEMENTS: &'static str = "entitlements";

    // Custom Claims (non-standard, application-specific)
    pub const TOKEN_USE: &'static str = "token_use";

    // JWS/JWK Header Parameters
    pub const ALG: &'static str = "alg";
    pub const TYP: &'static str = "typ";
    pub const KID: &'static str = "kid";
}

/// JWT Access Token media type as defined by RFC 9068 Section 2.1.
///
/// JWT access tokens MUST include this media type in the "typ" header parameter.
/// Per RFC 7515, it is RECOMMENDED that the "application/" prefix be omitted.
pub struct JwtTokenType;

impl JwtTokenType {
    /// Media type for JWT-formatted OAuth 2.0 access tokens (RFC 9068).
    /// Use this value in the JWT header "typ" claim.
    pub const ACCESS_TOKEN: &'static str = "at+jwt";

    /// Full media type with "application/" prefix.
    pub const ACCESS_TOKEN_FULL: &'static str = "application/at+jwt";
}

/// Token Type Identifiers as defined by RFC 8693 Section 3.
///
/// These URIs identify the type of security token being exchanged.
pub struct TokenTypeIdentifiers;

impl TokenTypeIdentifiers {
    pub const ACCESS_TOKEN: &'static str = "urn:ietf:params:oauth:token-type:access_token";
    pub const REFRESH_TOKEN: &'static str = "urn:ietf:params:oauth:token-type:refresh_token";
    pub const ID_TOKEN: &'static str = "urn:ietf:params:oauth:token-type:id_token";
    pub const JWT: &'static str = "urn:ietf:params:oauth:token-type:jwt";
    pub const SAML1: &'static str = "urn:ietf:params:oauth:token-type:saml1";
    pub const SAML2: &'static str = "urn:ietf:params:oauth:token-type:saml2";
}

/// Custom token use values for internal token type identification.
///
/// Note: This is a non-standard custom claim, not defined by RFC 8693.
/// RFC 8693 defines token type identifiers as URIs used in protocol parameters,
/// not as JWT claims. This custom claim is used internally to distinguish
/// token types within the application.
pub struct TokenUseValues;

impl TokenUseValues {
    pub const ACCESS_TOKEN: &'static str = "access_token";
    pub const REFRESH_TOKEN: &'static str = "refresh_token";
    pub const ID_TOKEN: &'static str = "id_token";
}

pub struct StandardScopes;

impl StandardScopes {
    pub const OPENID: &'static str = "openid";
    pub const PROFILE: &'static str = "profile";
    pub const EMAIL: &'static str = "email";
    pub const ADDRESS: &'static str = "address";
    pub const PHONE: &'static str = "phone";
    pub const OFFLINE_ACCESS: &'static str = "offline_access";
}
