//! Shared standard-claim output for token signers.

use identity_domain::{
    openid_connect::{ClaimsRequest, ScopeSet, model::claim::JwtClaimNames},
    user::User,
};
use serde_json::{Map, Value, to_value};

use super::UserInfoClaims;

/// Standard claims the granted `scope` (and, for the `id_token` section, an
/// optional `claims_request`) allow, as JSON object entries keyed by claim name.
/// `sub` is intentionally excluded: token signers set their own subject.
///
/// Shared by the implicit/hybrid ID Token signer and the token-endpoint signers
/// (when scoped claims are enabled for ID or access tokens) so the
/// scope/essential filtering rules never drift between them.
pub fn scoped_standard_claims(
    user: &User,
    scope: &ScopeSet,
    claims_request: Option<&ClaimsRequest>,
    profile_base_url: &str,
) -> Map<String, Value> {
    let mut claims = UserInfoClaims::from_user_with_profile_base(user, profile_base_url);
    claims.apply_scope_filter_for_id_token(scope, claims_request);

    // Serialization of the fully-typed claim struct is infallible (only
    // String/Option/bool fields); a failure here would indicate a bug and must
    // not silently drop claims.
    let mut claims = to_value(claims)
        .expect("UserInfoClaims serialization is infallible")
        .as_object()
        .cloned()
        .expect("UserInfoClaims serializes to an object");
    claims.remove(JwtClaimNames::SUB);
    claims
}
